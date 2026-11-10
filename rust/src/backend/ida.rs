//! Program analysis via IDA Pro, as a library (idalib): whatever IDA loads, for x86 and x64.
//!
//! IDA analyzes a file into a database, which this reads into a `Program`, and then closes:
//! the analyses and the emulator work from the `Program`, not from the database.
//! So the database is only used on the thread that opens it (IDA requires the main thread),
//! and something that already has an open database, like a plugin, can call `get_program`.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{c_char, c_int, c_uint, c_void, CStr},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use idalib::{
    func::FunctionFlags,
    idb::{IDBOpenOptions, IDB},
    meta::FileType,
};

use crate::program::{Arch, BasicBlock, Function, Import, Program, Segment, VA};

/// like vivisect's shellcode workspaces.
const SHELLCODE_BASE_ADDRESS: VA = 0x690000;

/// the SDK's `qstring`.
#[repr(C)]
struct QString {
    array: *mut c_char,
    n: usize,
    alloc: usize,
}

/// the SDK's `import_enum_cb_t`: returns zero to stop the enumeration.
type ImportCallback =
    extern "C" fn(ea: u64, name: *const c_char, ordinal: u64, param: *mut c_void) -> c_int;

// parts of the IDA SDK that idalib doesn't wrap. `ea_t`, `uval_t`, and `adiff_t` are 64 bits.
extern "C" {
    fn get_bytes(
        buf: *mut c_void,
        size: isize,
        ea: u64,
        gmb_flags: c_int,
        mask: *mut c_void,
    ) -> isize;
    fn is_debugger_on() -> bool;
    fn set_segment_addressing(ea: u64, bitness: usize) -> bool;
    fn setinf_flag(tag: c_int, flag: u32, value: bool) -> bool;
    fn rebase_program(delta: i64, flags: c_int) -> c_int;
    fn auto_mark_range(start: u64, end: u64, r#type: c_int);
    fn get_import_module_qty() -> c_uint;
    fn get_import_module_name(buf: *mut QString, mod_index: c_int) -> bool;
    fn enum_import_names(mod_index: c_int, callback: ImportCallback, param: *mut c_void) -> c_int;
    fn qfree(alloc: *mut c_void);
}

const GMB_READALL: c_int = 0x01;
const INF_LFLAGS: c_int = 3;
const LFLG_PC_FLAT: u32 = 0x2;
const LFLG_64BIT: u32 = 0x4;
const MSF_SILENT: c_int = 0x1;
const MSF_NOFIX: c_int = 0x2;
const AU_CODE: c_int = 20;
const AU_PROC: c_int = 30;

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// the file is raw shellcode for this architecture, which starts executing at its first byte.
    /// otherwise, IDA detects the file format.
    pub shellcode: Option<Arch>,
    /// the database to use: it's opened when it exists, and otherwise created from the file, and kept.
    /// without this, the database is temporary, and nothing is written next to the file.
    pub database:  Option<PathBuf>,
}

/// is this the path of an IDA database, rather than of a file to analyze?
pub fn is_database(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
        Some("i64" | "idb")
    )
}

/// The file that a database was made from, when it's next to the database
/// with the same name, less the extension: `sample.exe` for `sample.exe.i64`.
pub fn find_input_file(database: &Path) -> Option<PathBuf> {
    let path = database.with_extension("");
    (is_database(database) && path.is_file()).then_some(path)
}

/// Are IDA's libraries loaded into this process?
///
/// On macOS, they're weak libraries (see `build.rs`): when the dynamic linker doesn't find them,
/// the program still starts, and the address of each of their symbols is null.
/// Elsewhere, the program doesn't start without them.
pub fn is_loaded() -> bool {
    #[cfg(target_os = "macos")]
    return !unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"init_library".as_ptr()) }.is_null();
    #[cfg(not(target_os = "macos"))]
    true
}

/// Check that IDA can be used: its libraries are loaded, it starts, and it has a license.
///
/// This starts IDA, which stays loaded, so it must be called from the main thread.
pub fn validate_available() -> Result<()> {
    ensure!(
        is_loaded(),
        "IDA's libraries (libida and libidalib) aren't found"
    );
    // idalib panics when IDA doesn't start.
    let has_license = std::panic::catch_unwind(idalib::license::is_valid_license)
        .map_err(|_| anyhow!("IDA doesn't start"))?;
    ensure!(has_license, "IDA doesn't have a valid license");
    Ok(())
}

/// Analyze a file with IDA, or open its existing database, and read the program from it.
///
/// `path` is the file to analyze, or an IDA database (.i64/.idb), which is opened as it is.
/// This must be called from the main thread, and the database is closed when it returns.
pub fn load(path: &Path, opts: &Options) -> Result<Program> {
    ensure!(
        is_loaded(),
        "IDA's libraries (libida and libidalib) aren't found"
    );
    let session = Session::open(path, opts)?;
    get_program(&session.idb)
}

/// An open database, and the temporary directory that it's in, if any.
struct Session {
    // fields drop in order: the database closes before its directory is removed.
    idb:  IDB,
    _dir: Option<tempfile::TempDir>,
}

impl Session {
    fn open(path: &Path, opts: &Options) -> Result<Session> {
        let existing = if is_database(path) {
            Some(path)
        } else {
            opts.database.as_deref().filter(|database| database.exists())
        };
        if let Some(database) = existing {
            log::info!("opening the IDA database {}", database.display());
            let idb = IDBOpenOptions::new()
                .auto_analyse(false)
                .save(false)
                .open(database)
                .map_err(|e| anyhow!("IDA can't open the database {}: {e}", database.display()))?;
            return Ok(Session { idb, _dir: None });
        }

        let mut options = IDBOpenOptions::new();
        options.auto_analyse(true);

        let dir = match &opts.database {
            Some(database) => {
                options.idb(database).save(true);
                None
            }
            None => {
                let dir = tempfile::tempdir().context("create a directory for the IDA database")?;
                let name = path.file_name().context("the path has no file name")?;
                options.idb(dir.path().join(name).with_extension("i64")).save(false);
                Some(dir)
            }
        };

        log::info!("analyzing {} with IDA", path.display());
        let mut idb = options
            .open(path)
            .map_err(|e| anyhow!("IDA can't analyze {}: {e}", path.display()))?;

        match opts.shellcode {
            Some(arch) => analyze_shellcode(&mut idb, arch)?,
            None if matches!(idb.meta().filetype(), FileType::BIN) => {
                bail!("IDA doesn't recognize the format of the file (if it's shellcode, give its architecture)")
            }
            None => {}
        }

        Ok(Session { idb, _dir: dir })
    }
}

/// IDA loads a binary file as data, at address zero:
/// move it, set the bitness, and disassemble from the first byte.
fn analyze_shellcode(idb: &mut IDB, arch: Arch) -> Result<()> {
    let file_type = idb.meta().filetype();
    if !matches!(file_type, FileType::BIN) {
        bail!("IDA detects that the file has a format ({file_type:?}), so it isn't shellcode");
    }
    let get_starts = |idb: &IDB| -> Vec<VA> {
        idb.segments()
            .map(|(_, segment)| segment.start_address())
            .collect()
    };
    let Some(start) = get_starts(idb).into_iter().min() else {
        bail!("IDA loaded no segments");
    };
    // SAFETY: the database is open, and this is the thread that opened it.
    if unsafe {
        rebase_program(
            SHELLCODE_BASE_ADDRESS.wrapping_sub(start) as i64,
            MSF_SILENT | MSF_NOFIX,
        )
    } != 0
    {
        bail!("IDA can't move the shellcode to {SHELLCODE_BASE_ADDRESS:#x}");
    }
    let starts = get_starts(idb);
    let entry = SHELLCODE_BASE_ADDRESS;

    // SAFETY: as above.
    unsafe {
        setinf_flag(INF_LFLAGS, LFLG_PC_FLAT, true);
        setinf_flag(INF_LFLAGS, LFLG_64BIT, arch == Arch::X64);
        for &start in starts.iter() {
            let bitness = match arch {
                Arch::X32 => 1,
                Arch::X64 => 2,
            };
            if !set_segment_addressing(start, bitness) {
                bail!("IDA can't set the bitness of the segment at {start:#x}");
            }
        }
        auto_mark_range(entry, entry + 1, AU_CODE);
        auto_mark_range(entry, entry + 1, AU_PROC);
    }
    idb.auto_wait();
    Ok(())
}

/// Read the program from an open database: segments, functions, control flow, and imports.
pub fn get_program(idb: &IDB) -> Result<Program> {
    let processor = idb.processor();
    if !processor.family().is_386() {
        bail!(
            "unsupported processor: {} (only x86 and x64)",
            processor.short_name()
        );
    }
    let meta = idb.meta();
    let base_address = idb.image_base();
    let arch = if meta.is_64bit() {
        Arch::X64
    } else if meta.is_32bit_exactly() {
        Arch::X32
    } else {
        bail!("unsupported processor mode: 16-bit");
    };

    let mut thunks: BTreeSet<VA> = Default::default();
    let mut library_functions: BTreeSet<VA> = Default::default();
    let mut function_names: BTreeMap<VA, String> = Default::default();
    let mut functions = vec![];
    let segments = get_segments(idb)?;
    for (_, func) in idb.functions() {
        let fva = func.start_address();
        if !segments
            .iter()
            .any(|segment| (segment.va..segment.end()).contains(&fva))
        {
            continue;
        }
        let Some(function) = get_function(idb, &func)? else {
            log::debug!("function {fva:#x} has no code");
            continue;
        };
        functions.push(function);

        let flags = func.flags();
        if flags.contains(FunctionFlags::THUNK) {
            thunks.insert(fva);
        }
        if flags.contains(FunctionFlags::LIB) {
            library_functions.insert(fva);
        }
        if let Some(name) = func.name().filter(|name| !name.starts_with("sub_")) {
            function_names.insert(fva, name);
        }
    }

    Ok(Program {
        arch,
        base_address,
        segments,
        functions,
        thunks,
        library_functions,
        function_names,
        imports: get_imports(),
    })
}

/// The import table entries of the open database.
fn get_imports() -> Vec<Import> {
    extern "C" fn collect(ea: u64, name: *const c_char, ordinal: u64, param: *mut c_void) -> c_int {
        // SAFETY: `param` is the vector that `get_imports` passes to `enum_import_names`,
        // and `name` is a C string, or null for an import by ordinal.
        let (names, name) = unsafe {
            let names = &mut *(param as *mut Vec<(VA, String)>);
            let name =
                (!name.is_null()).then(|| CStr::from_ptr(name).to_string_lossy().into_owned());
            (names, name)
        };
        names.push((
            ea,
            name.filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("#{ordinal}")),
        ));
        1
    }

    let mut imports = vec![];
    // SAFETY: a database is open, and this is the thread that opened it.
    // `get_import_module_name` allocates the string, which `qfree` releases.
    unsafe {
        for index in 0..get_import_module_qty() as c_int {
            let mut buf = QString {
                array: std::ptr::null_mut(),
                n: 0,
                alloc: 0,
            };
            let mut dll = String::new();
            if get_import_module_name(&mut buf, index) && !buf.array.is_null() {
                dll = CStr::from_ptr(buf.array).to_string_lossy().to_lowercase();
            }
            qfree(buf.array.cast());
            let dll = dll.strip_suffix(".dll").unwrap_or(&dll).to_string();

            let mut names: Vec<(VA, String)> = vec![];
            enum_import_names(
                index,
                collect,
                (&mut names as *mut Vec<(VA, String)>).cast(),
            );
            imports.extend(names.into_iter().map(|(va, name)| Import {
                va,
                dll: dll.clone(),
                name,
            }));
        }
    }
    imports
}

fn get_segments(idb: &IDB) -> Result<Vec<Segment>> {
    // SAFETY: a database is open, and this is the thread that opened it.
    if unsafe { is_debugger_on() } {
        log::warn!(
            "a debugger is active in IDA, started by a plugin: the database has the memory of the running \
             program, not the contents of the file, so strings can be missing"
        );
    }

    let mut segments = vec![];
    for (_, segment) in idb.segments() {
        let va = segment.start_address();
        let size = segment.len();
        // a debugger's segments, like its stack and the modules that it loads, aren't the program's.
        if size == 0 || segment.is_debugger() {
            continue;
        }

        let permissions = segment.permissions();
        segments.push(Segment {
            va,
            name: segment.name().unwrap_or_default(),
            // a segment without permissions is one whose permissions the loader doesn't know.
            executable: permissions.is_executable() || permissions.is_empty(),
            bytes: get_bytes_or_zeros(va, size)?,
        });
    }
    Ok(segments)
}

/// The bytes at the address. Those without a value, like the bytes of .bss, are zero,
/// as they are when the program starts.
fn get_bytes_or_zeros(va: VA, size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    // a bit for each byte: set when the byte has a value.
    let mut mask = vec![0u8; size.div_ceil(8)];
    // SAFETY: a database is open, and this is the thread that opened it.
    // the buffers have the sizes that `get_bytes` documents: `size`, and `(size + 7) / 8`.
    let read = unsafe {
        get_bytes(
            bytes.as_mut_ptr().cast(),
            size as isize,
            va,
            GMB_READALL,
            mask.as_mut_ptr().cast(),
        )
    };
    if read < 0 {
        bail!("IDA can't read {size:#x} bytes at {va:#x}");
    }
    for (i, byte) in bytes.iter_mut().enumerate() {
        if mask[i / 8] & (1 << (i % 8)) == 0 {
            *byte = 0;
        }
    }
    Ok(bytes)
}

/// The function's basic blocks, or None when it has no instructions at its start.
fn get_function(idb: &IDB, func: &idalib::func::Function) -> Result<Option<Function>> {
    let fva = func.start_address();
    let cfg = func
        .cfg()
        .map_err(|e| anyhow!("IDA can't make the flow chart of function {fva:#x}: {e}"))?;

    let mut blocks: BTreeMap<VA, BasicBlock> = Default::default();
    for bb in cfg.blocks() {
        // extern blocks are the targets of jumps out of the function, like tail calls.
        if bb.is_extern() {
            continue;
        }
        let va = bb.start_address();
        let end = bb.end_address();
        let insns: Vec<VA> = std::iter::successors(Some(va), |&ea| idb.next_head_with(ea, end))
            .filter(|&ea| idb.flags_at(ea).is_code())
            .collect();
        if insns.is_empty() {
            continue;
        }
        blocks.insert(va, BasicBlock {
            va,
            insns,
            successors: bb.succs_with(&cfg).map(|succ| succ.start_address()).collect(),
        });
    }

    let starts: BTreeSet<VA> = blocks.keys().copied().collect();
    for bb in blocks.values_mut() {
        bb.successors.retain(|succ| starts.contains(succ));
    }

    Ok(blocks.contains_key(&fva).then_some(Function { va: fva, blocks }))
}
