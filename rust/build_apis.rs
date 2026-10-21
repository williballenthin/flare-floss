//! generate the table of how many bytes of arguments each Windows API pops
//! from the stack when it returns, on 32-bit x86. see `src/emu/api.rs`.
//!
//! the sources, both git submodules in `deps/`:
//!
//!   - win32json: Microsoft's win32metadata (the Windows SDK's API declarations) as JSON.
//!   - phnt: the native API headers from System Informer (`Nt*`, `Rtl*`, `Ldr*`, ...),
//!     which win32metadata mostly leaves out.
//!
//! and `data/apis-x86-overrides.tsv`, for what neither gets right.
//!
//! the output has one line per API: DLL (lowercase, without extension), name, and bytes.
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};

use regex::Regex;
use serde_json::Value;

/// (dll, name) -> bytes of arguments the callee pops.
type Table = BTreeMap<(String, String), u32>;

pub fn generate(root: &Path, out: &Path) {
    let win32json = root.join("deps").join("win32json").join("api");
    let phnt = root.join("deps").join("phnt");
    let overrides = root.join("data").join("apis-x86-overrides.tsv");
    for dir in [&win32json, &phnt] {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    println!("cargo:rerun-if-changed={}", overrides.display());

    let docs: Vec<Value> = sorted_files(&win32json, "json")
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).unwrap();
            let mut doc: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap();
            // the namespace, like `System.LibraryLoader`, is the file name.
            doc["_namespace"] = path.file_stem().unwrap().to_str().unwrap().into();
            doc
        })
        .collect();
    let types = Types::new(&docs);

    let mut table = Table::new();
    from_win32json(&docs, &types, &mut table);
    from_phnt(&phnt, &types, &mut table);
    apply_overrides(&fs::read_to_string(&overrides).unwrap(), &mut table);

    let mut tsv = String::new();
    for ((dll, name), bytes) in &table {
        tsv.push_str(&format!("{dll}\t{name}\t{bytes}\n"));
    }
    fs::write(out, tsv).unwrap();
}

fn sorted_files(dir: &Path, extension: &str) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == extension))
        .collect();
    paths.sort();
    paths
}

/// `KERNEL32.dll` -> `kernel32`, `winspool.drv` -> `winspool`.
fn normalize_dll(dll: &str) -> String {
    let dll = dll.to_lowercase();
    match dll.rsplit_once('.') {
        Some((stem, "dll" | "drv" | "exe" | "cpl" | "sys" | "ocx")) => stem.to_string(),
        _ => dll,
    }
}

/// arguments take 4-byte stack slots.
fn slots(size: u32) -> u32 {
    size.next_multiple_of(4)
}

/// win32metadata's types, for sizes of arguments passed by value.
struct Types<'a> {
    /// (namespace, name) -> definition
    by_namespace: HashMap<(&'a str, &'a str), &'a Value>,
    /// name -> definition, for phnt, which uses the same names
    by_name: HashMap<&'a str, &'a Value>,
}

impl<'a> Types<'a> {
    fn new(docs: &'a [Value]) -> Self {
        let mut by_namespace = HashMap::new();
        let mut by_name = HashMap::new();
        for doc in docs {
            let namespace = doc["_namespace"].as_str().unwrap_or_default();
            for t in doc["Types"].as_array().unwrap() {
                let name = t["Name"].as_str().unwrap();
                by_namespace.insert((namespace, name), t);
                by_name.entry(name).or_insert(t);
            }
        }
        Types { by_namespace, by_name }
    }

    /// size and alignment of a type reference, on x86.
    /// `scopes` are the structs being laid out, whose nested types are in scope.
    fn size_align(&self, t: &'a Value, scopes: &mut Vec<&'a Value>) -> Option<(u32, u32)> {
        match t["Kind"].as_str()? {
            "Native" => native_size(t["Name"].as_str()?).map(|s| (s, s.clamp(1, 8))),
            "PointerTo" | "LPArray" => Some((4, 4)),
            "Array" => {
                let (size, align) = self.size_align(&t["Child"], scopes)?;
                Some((size * t["Shape"]["Size"].as_u64()? as u32, align))
            }
            "ApiRef" => {
                if matches!(t["TargetKind"].as_str()?, "Com" | "FunctionPointer") {
                    return Some((4, 4));
                }
                let name = t["Name"].as_str()?;
                for i in (0..scopes.len()).rev() {
                    let nested = scopes[i]["NestedTypes"].as_array()?;
                    if let Some(def) = nested.iter().find(|n| n["Name"] == name) {
                        let mut enclosing = scopes[..=i].to_vec();
                        return self.layout(def, &mut enclosing);
                    }
                }
                let def = self.by_namespace.get(&(t["Api"].as_str()?, name))?;
                self.definition_size(def)
            }
            _ => None,
        }
    }

    fn definition_size(&self, def: &'a Value) -> Option<(u32, u32)> {
        match def["Kind"].as_str()? {
            "NativeTypedef" => self.size_align(&def["Def"], &mut vec![]),
            "Enum" => {
                let size = native_size(def["IntegerBase"].as_str().unwrap_or("Int32"))?;
                Some((size, size))
            }
            "Struct" | "Union" => self.layout(def, &mut vec![]),
            "Com" | "FunctionPointer" => Some((4, 4)),
            _ => None,
        }
    }

    /// C layout of a struct or union, with its packing.
    fn layout(&self, def: &'a Value, scopes: &mut Vec<&'a Value>) -> Option<(u32, u32)> {
        let union = def["Kind"] == "Union";
        let pack = def["PackingSize"].as_u64().unwrap_or(0) as u32;
        scopes.push(def);
        let (mut size, mut align) = (0, 1);
        for field in def["Fields"].as_array()? {
            let (field_size, mut field_align) = self.size_align(&field["Type"], scopes)?;
            if pack > 0 {
                field_align = field_align.min(pack);
            }
            align = align.max(field_align);
            size = if union {
                size.max(field_size)
            } else {
                size.next_multiple_of(field_align) + field_size
            };
        }
        scopes.pop();
        Some((size.next_multiple_of(align), align))
    }
}

/// size of win32metadata's native types, on x86.
fn native_size(name: &str) -> Option<u32> {
    Some(match name {
        "Void" => 0,
        "Byte" | "SByte" | "Boolean" => 1,
        "Char" | "UInt16" | "Int16" => 2,
        "UInt32" | "Int32" | "Single" | "IntPtr" | "UIntPtr" => 4,
        "UInt64" | "Int64" | "Double" => 8,
        "Guid" => 16,
        _ => return None,
    })
}

/// win32metadata records no calling convention: Windows APIs are stdcall,
/// so the callee pops all of its arguments. the exceptions are in the overrides.
fn from_win32json<'a>(docs: &'a [Value], types: &Types<'a>, table: &mut Table) {
    for doc in docs {
        for f in doc["Functions"].as_array().unwrap() {
            let architectures = f["Architectures"].as_array().unwrap();
            if !architectures.is_empty() && !architectures.iter().any(|a| a == "X86") {
                continue;
            }
            let bytes: Option<u32> = f["Params"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| types.size_align(&p["Type"], &mut vec![]).map(|(size, _)| slots(size)))
                .sum();
            let Some(bytes) = bytes else {
                println!("cargo:warning=win32json: can't size the arguments of {}", f["Name"]);
                continue;
            };
            let dll = normalize_dll(f["DllImport"].as_str().unwrap());
            let name = f["Name"].as_str().unwrap();
            // since Windows 7, the psapi functions are kernel32 exports with a K32 prefix,
            // and win32metadata only has those; but programs import them from psapi, too.
            if let ("kernel32", Some(psapi)) = (dll.as_str(), name.strip_prefix("K32")) {
                table.insert(("psapi".into(), psapi.into()), bytes);
            }
            table.insert((dll, name.into()), bytes);
        }
    }
}

/// phnt's prototypes look like:
///
/// ```c
/// NTSYSCALLAPI
/// NTSTATUS
/// NTAPI
/// NtOpenProcess(
///     _Out_ PHANDLE ProcessHandle,
///     _In_ ACCESS_MASK DesiredAccess,
///     _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
///     _In_opt_ PCLIENT_ID ClientId
///     );
/// ```
///
/// with the calling convention on the line before the name. inline functions
/// (`NTAPI_INLINE`, or with a body) aren't exports, so they're skipped.
/// everything in phnt is taken to be an ntdll export, and doesn't replace win32metadata's entries.
fn from_phnt(dir: &Path, types: &Types, table: &mut Table) {
    let comments = Regex::new(r"(?s)/\*.*?\*/|//[^\n]*").unwrap();
    let prototype = Regex::new(
        r"(?m)^[ \t]*(NTAPI|WINAPI|FASTCALL|STDAPIVCALLTYPE)[ \t]*\n[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(([^;{]*?)\)[ \t]*;",
    )
    .unwrap();

    for path in sorted_files(dir, "h") {
        let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        let text = comments.replace_all(&text, "");
        for m in prototype.captures_iter(&text) {
            let key = ("ntdll".to_string(), m[2].to_string());
            if table.contains_key(&key) {
                continue;
            }
            let params = split_params(&m[3]);
            let bytes = match &m[1] {
                // cdecl: the caller pops.
                _ if params.iter().any(|p| p == "...") => 0,
                "STDAPIVCALLTYPE" => 0,
                // the first two arguments are in ecx and edx.
                "FASTCALL" => params.iter().skip(2).map(|p| slots(phnt_param_size(p, types))).sum(),
                _ => params.iter().map(|p| slots(phnt_param_size(p, types))).sum(),
            };
            table.insert(key, bytes);
        }
    }
}

/// split a parameter list at its top-level commas, dropping SAL annotations
/// like `_In_` and `_Out_writes_bytes_(Length)`. `VOID` is no parameters.
fn split_params(list: &str) -> Vec<String> {
    let mut params = vec![String::new()];
    let mut depth = 0;
    let mut annotation_depth = None;
    let mut word = String::new();
    let flush = |word: &mut String, params: &mut Vec<String>, annotation: bool| {
        if !annotation && !word.is_empty() {
            let param = params.last_mut().unwrap();
            if !param.is_empty() {
                param.push(' ');
            }
            param.push_str(word);
        }
        word.clear();
    };
    for c in list.chars().chain([' ']) {
        if c.is_alphanumeric() || c == '_' || c == '.' {
            word.push(c);
            continue;
        }
        // SAL annotations start and end with an underscore: `_In_`, `_Inout_opt_`.
        let is_annotation = word.len() > 1 && word.starts_with('_') && word.ends_with('_');
        if is_annotation && annotation_depth.is_none() && depth == 0 && c == '(' {
            annotation_depth = Some(depth);
        }
        flush(&mut word, &mut params, is_annotation || annotation_depth.is_some());
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if annotation_depth == Some(depth) {
                    annotation_depth = None;
                }
            }
            ',' if depth == 0 => params.push(String::new()),
            '*' | '[' if annotation_depth.is_none() => params.last_mut().unwrap().push_str(" *"),
            _ => {}
        }
    }
    params.retain(|p| !p.is_empty() && p != "VOID" && p != "void");
    params
}

/// the size of a phnt parameter, like `PHANDLE ProcessHandle` or `LARGE_INTEGER Interval`.
/// types win32metadata knows get its sizes; all others are 4 bytes:
/// phnt's own types are handles, pointers, enums and 32-bit integers.
fn phnt_param_size(param: &str, types: &Types) -> u32 {
    if param.contains('*') {
        return 4;
    }
    let words: Vec<&str> = param
        .split(' ')
        .filter(|w| !matches!(*w, "const" | "CONST" | "struct" | "union" | "enum" | "volatile"))
        .collect();
    // the last word is the name, unless it's the only one.
    let ty = if words.len() > 1 { words[words.len() - 2] } else { words[0] };
    match ty {
        "LONGLONG" | "ULONGLONG" | "LONG64" | "ULONG64" | "DWORD64" | "INT64" | "UINT64" | "DWORDLONG" | "__int64"
        | "double" | "DOUBLE" => 8,
        "GUID" => 16,
        _ => types
            .by_name
            .get(ty)
            .and_then(|def| types.definition_size(def))
            .map_or(4, |(size, _)| size),
    }
}

/// lines of `dll.name` (or `dll.*`, every function of the DLL), and the bytes the callee pops.
fn apply_overrides(text: &str, table: &mut Table) {
    for line in text.lines().filter(|line| !line.starts_with('#') && !line.trim().is_empty()) {
        let mut parts = line.split('\t').filter(|p| !p.is_empty());
        let (Some(api), Some(bytes)) = (parts.next(), parts.next()) else {
            panic!("bad override: {line:?}");
        };
        let (dll, name) = api.split_once('.').expect("overrides are dll.name");
        let bytes: u32 = bytes.parse().expect("overrides give a number of bytes");
        if name == "*" {
            table.iter_mut().filter(|((d, _), _)| d == dll).for_each(|(_, b)| *b = bytes);
        } else {
            table.insert((dll.into(), name.into()), bytes);
        }
    }
}
