//! Calls to imported APIs and recognized library functions.
//!
//! When execution reaches an API, the emulator returns to the caller
//! right away. With API models enabled, a few common functions get a
//! simple implementation first (allocate memory, copy bytes, ...), so
//! that code that decodes strings into buffers it got from `malloc`,
//! or via `memcpy`, still works. These are the same models as FLOSS's
//! `api_hooks.py`. Everything else returns 0.
//!
//! The loader-ish functions (LoadLibrary, GetProcAddress, GetModuleHandle)
//! are always modeled, like vivisect's default hooks, so that
//! dynamically resolved imports become stubs, too.
use std::{collections::HashMap, sync::OnceLock};

use lancelot::{arch::Arch, VA};

use super::Emulator;

/// the module name reported by GetModuleFileName.
const MODULE_FILENAME: &str = "C:\\Users\\flare\\program.exe";
const CURRENT_PROCESS: u64 = 7331;
const PROCESS_HEAP: u64 = 42;
const MAX_STRING: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Convention {
    /// callee pops the arguments.
    Stdcall,
    /// caller pops the arguments.
    Cdecl,
    /// first two arguments in registers, callee pops the rest.
    Fastcall,
}

/// calling convention and argument count, by lowercase "dll.name", for x86.
fn x86_apis() -> &'static HashMap<String, (Convention, u8)> {
    static APIS: OnceLock<HashMap<String, (Convention, u8)>> = OnceLock::new();
    APIS.get_or_init(|| {
        include_str!("../../data/apis-x86.tsv")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let mut parts = line.split('\t');
                let name = parts.next()?;
                let conv = match parts.next()? {
                    "cdecl" => Convention::Cdecl,
                    "msfastcall" | "bfastcall" => Convention::Fastcall,
                    _ => Convention::Stdcall,
                };
                let argc = parts.next()?.parse().ok()?;
                Some((name.to_string(), (conv, argc)))
            })
            .collect()
    })
}

/// How many bytes of arguments the callee pops when returning from the given function.
fn callee_cleanup(emu: &Emulator, target: VA, name: &str) -> u64 {
    if let Arch::X64 = emu.arch {
        return 0;
    }

    if emu.stub_at(target).is_some() {
        match x86_apis().get(&name.to_lowercase()) {
            Some((Convention::Stdcall, argc)) => 4 * *argc as u64,
            Some((Convention::Fastcall, argc)) => 4 * argc.saturating_sub(2) as u64,
            // unknown APIs are treated like vivisect does: stdcall, no arguments.
            Some((Convention::Cdecl, _)) | None => 0,
        }
    } else {
        // a function in the program: we found its `ret N` during analysis.
        emu.callee_cleanup.get(&target).copied().unwrap_or(0) as u64
    }
}

/// normalize a function name for matching against the models:
/// drop the DLL, decorations, and leading underscores, and lowercase it.
///
///   kernel32.VirtualAlloc -> virtualalloc
///   _malloc               -> malloc
///   _HeapAlloc@12         -> heapalloc
fn normalize(name: &str) -> String {
    let name = name.rsplit('.').next().unwrap_or(name);
    let name = name.strip_prefix("j_").unwrap_or(name);
    let name = name.trim_start_matches('_');
    let name = match name.find('@') {
        // keep C++ mangled names, like ??2@YAPAXI@Z, intact.
        Some(i) if i > 0 && !name.starts_with('?') => &name[..i],
        _ => name,
    };
    name.to_lowercase()
}

/// What a model decided.
enum Outcome {
    /// return to the caller with this value.
    Return(u64),
    /// the model doesn't apply to this call (like FLOSS hooks that decline); return 0.
    Decline,
    /// stop emulating, like after ExitProcess.
    Stop,
}

type Model = fn(&mut Emulator, &str) -> Outcome;

/// models that are always enabled: they turn dynamically resolved APIs into stubs.
const LOADER_MODELS: &[(&[&str], Model)] = &[
    (
        &["loadlibrarya", "loadlibraryexa", "getmodulehandlea"],
        |emu, _| load_library(emu, false),
    ),
    (
        &["loadlibraryw", "loadlibraryexw", "getmodulehandlew"],
        |emu, _| load_library(emu, true),
    ),
    (&["getmodulehandleexa"], |emu, _| get_module_handle_ex(emu, false)),
    (&["getmodulehandleexw"], |emu, _| get_module_handle_ex(emu, true)),
    (&["getprocaddress"], get_proc_address),
];

/// FLOSS's API hooks.
const MODELS: &[(&[&str], Model)] = &[
    (&["getprocessheap"], |_, _| Outcome::Return(PROCESS_HEAP)),
    (&["getmodulefilenamea"], |emu, _| get_module_filename(emu, 0, false)),
    (&["getmodulefilenamew"], |emu, _| get_module_filename(emu, 0, true)),
    (&["getmodulefilenameexa"], |emu, _| get_module_filename(emu, 1, false)),
    (&["getmodulefilenameexw"], |emu, _| get_module_filename(emu, 1, true)),
    (&["malloc", "malloc_base"], |emu, _| allocate_arg(emu, 0)),
    (&["virtualalloc", "localalloc", "globalalloc"], |emu, _| allocate_arg(emu, 1)),
    (&["virtualallocex", "heapalloc", "rtlallocateheap"], |emu, _| allocate_arg(emu, 2)),
    (&["calloc", "calloc_base"], |emu, _| {
        let size = emu.arg(0).saturating_mul(emu.arg(1));
        allocate(emu, size)
    }),
    // C++ operator new and new[]
    (&["znwj", "znaj", "??2@yapaxi@z", "??2@yapeax_k@z"], |emu, _| allocate_arg(emu, 0)),
    (&["free", "free_base", "virtualfree", "heapfree", "rtlfreeheap"], |_, _| Outcome::Return(1)),
    (&["exitprocess", "raiseexception"], |_, _| Outcome::Stop),
    (&["terminateprocess"], |emu, _| {
        if emu.arg(0) == CURRENT_PROCESS {
            Outcome::Stop
        } else {
            Outcome::Decline
        }
    }),
    (
        &["eh_prolog", "eh_prolog3", "seh_prolog4", "seh4_prolog", "seh_epilog4", "security_check_cookie"],
        |_, _| Outcome::Return(0),
    ),
    (&["memcpy", "memmove"], |emu, _| {
        let (dst, src, n) = (emu.arg(0), emu.arg(1), emu.arg(2));
        copy(emu, dst, src, n)
    }),
    (&["memcpy_s", "wmemcpy_s"], |emu, _| {
        let (dst, src, n) = (emu.arg(0), emu.arg(2), emu.arg(3));
        copy(emu, dst, src, n)
    }),
    (&["strlen", "lstrlena"], |emu, _| {
        let s = emu.arg(0);
        Outcome::Return(emu.read_cstr(s, MAX_STRING, false).len() as u64)
    }),
    (&["wcslen", "lstrlenw"], |emu, _| {
        let s = emu.arg(0);
        Outcome::Return(emu.read_cstr(s, MAX_STRING, true).len() as u64)
    }),
    (&["strnlen"], |emu, _| {
        let (s, max) = (emu.arg(0), emu.arg(1));
        Outcome::Return(emu.read_cstr(s, (max as usize).min(MAX_STRING), false).len() as u64)
    }),
    (&["strncmp"], |emu, _| {
        let (a, b, n) = (emu.arg(0), emu.arg(1), emu.arg(2));
        let n = (n as usize).min(MAX_STRING);
        let a = emu.read_cstr(a, n, false);
        let b = emu.read_cstr(b, n, false);
        Outcome::Return(match a.cmp(&b) {
            std::cmp::Ordering::Less => u64::MAX,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        })
    }),
    (&["memchr"], |emu, _| {
        let (p, value, n) = (emu.arg(0), emu.arg(1), emu.arg(2));
        let buf = emu.read_mem(p, (n as usize).min(super::MAX_ALLOCATION as usize));
        Outcome::Return(match buf.iter().position(|&b| b == value as u8) {
            Some(i) => p + i as u64,
            None => 0,
        })
    }),
    (&["memset"], |emu, _| {
        let (p, value, n) = (emu.arg(0), emu.arg(1), emu.arg(2));
        let buf = vec![value as u8; (n as usize).min(super::MAX_ALLOCATION as usize)];
        let _ = emu.write_mem(p, &buf);
        Outcome::Return(p)
    }),
    (&["sprintf"], |emu, _| sprintf(emu, false)),
    (&["snprintf"], |emu, _| sprintf(emu, true)),
    (&["getlasterror"], |_, _| Outcome::Return(0)),
    (&["getcurrentprocess"], |_, _| Outcome::Return(CURRENT_PROCESS)),
    (&["initializecriticalsection"], |emu, _| {
        let p = emu.arg(0);
        let _ = emu.write_mem(p, b"CS");
        Outcome::Return(0)
    }),
];

fn find(models: &'static [(&'static [&'static str], Model)], name: &str) -> Option<Model> {
    models
        .iter()
        .find(|(names, _)| names.contains(&name))
        .map(|(_, model)| *model)
}

/// Is there a model for this function? used to decide whether to
/// emulate a library function in the program, or model it.
pub fn find_model(name: &str) -> Option<()> {
    let name = normalize(name);
    find(MODELS, &name).or_else(|| find(LOADER_MODELS, &name)).map(|_| ())
}

/// Handle a call to the API or library function `name` at `target`:
/// the return address is on the top of the stack.
/// Returns true when emulation should stop.
pub fn call(emu: &mut Emulator, target: VA, name: &str, models: bool) -> bool {
    let normalized = normalize(name);
    let mut model = find(LOADER_MODELS, &normalized);
    if models && model.is_none() {
        model = find(MODELS, &normalized);
    }

    let outcome = match model {
        Some(model) => model(emu, name),
        None => Outcome::Decline,
    };

    let value = match outcome {
        Outcome::Return(value) => value,
        Outcome::Decline => 0,
        Outcome::Stop => return true,
    };

    let cleanup = callee_cleanup(emu, target, name);
    emu.return_from_call(value, cleanup);
    false
}

/// allocate the size given by the `index`th argument.
fn allocate_arg(emu: &mut Emulator, index: usize) -> Outcome {
    let size = emu.arg(index);
    allocate(emu, size)
}

fn allocate(emu: &mut Emulator, size: u64) -> Outcome {
    match emu.allocate(size) {
        Ok(va) => Outcome::Return(va),
        Err(_) => Outcome::Return(0),
    }
}

fn copy(emu: &mut Emulator, dst: VA, src: VA, n: u64) -> Outcome {
    let n = n.min(super::MAX_ALLOCATION) as usize;
    let buf = emu.read_mem(src, n);
    let _ = emu.write_mem(dst, &buf);
    Outcome::Return(dst)
}

/// the library name, lowercase and without extension, like vivisect's `readLibraryPath`.
fn read_library_name(emu: &mut Emulator, va: VA, wide: bool) -> String {
    let name = String::from_utf8_lossy(&emu.read_cstr(va, 260, wide)).to_lowercase();
    let name = name.rsplit(['\\', '/']).next().unwrap_or(&name).to_string();
    match name.split('.').next() {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => "unknownlib".to_string(),
    }
}

fn load_library(emu: &mut Emulator, wide: bool) -> Outcome {
    let p = emu.arg(0);
    let name = read_library_name(emu, p, wide);
    Outcome::Return(emu.module_handle(&name))
}

fn get_module_handle_ex(emu: &mut Emulator, wide: bool) -> Outcome {
    let (p, out) = (emu.arg(1), emu.arg(2));
    let name = read_library_name(emu, p, wide);
    let handle = emu.module_handle(&name);
    let _ = emu.write_ptr(out, handle);
    Outcome::Return(1)
}

fn get_proc_address(emu: &mut Emulator, _: &str) -> Outcome {
    let (handle, p) = (emu.arg(0), emu.arg(1));
    let dll = emu.module_name(handle).unwrap_or("unknownlib").to_string();
    let name = if p < 0x10000 {
        format!("#{p}")
    } else {
        String::from_utf8_lossy(&emu.read_cstr(p, 260, false)).to_string()
    };
    Outcome::Return(emu.stub_for(&dll, &name))
}

/// `filename_arg` is the index of the hModule argument.
fn get_module_filename(emu: &mut Emulator, module_arg: usize, wide: bool) -> Outcome {
    let (module, buf) = (emu.arg(module_arg), emu.arg(module_arg + 1));
    if module != 0 {
        return Outcome::Decline;
    }
    let data: Vec<u8> = if wide {
        MODULE_FILENAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|c| c.to_le_bytes())
            .collect()
    } else {
        MODULE_FILENAME.bytes().chain(std::iter::once(0)).collect()
    };
    let _ = emu.write_mem(buf, &data);
    Outcome::Return(MODULE_FILENAME.len() as u64)
}

/// a small printf, enough for format strings that build paths and names:
/// `%s %d %i %u %x %X %c %o %%` with flags, width, and precision.
fn sprintf(emu: &mut Emulator, bounded: bool) -> Outcome {
    let (buf, size, fmt_ptr, mut next_arg) = if bounded {
        (emu.arg(0), emu.arg(1) as usize, emu.arg(2), 3)
    } else {
        (emu.arg(0), MAX_STRING, emu.arg(1), 2)
    };
    let fmt = emu.read_cstr(fmt_ptr, 256, false);

    let mut out: Vec<u8> = vec![];
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i]);
            i += 1;
            continue;
        }
        if fmt.get(i + 1) == Some(&b'%') {
            out.push(b'%');
            i += 2;
            continue;
        }

        let start = i;
        i += 1;
        while i < fmt.len() && b"0123456789+-# .hlL".contains(&fmt[i]) {
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            break;
        };
        i += 1;

        let spec = String::from_utf8_lossy(&fmt[start + 1..i - 1]).to_string();
        let width: usize = spec
            .trim_start_matches(['-', '+', '#', ' ', '0'])
            .split('.')
            .next()
            .and_then(|w| w.trim_end_matches(['h', 'l', 'L']).parse().ok())
            .unwrap_or(0);
        let zero_pad = spec.starts_with('0');
        let left = spec.starts_with('-');

        let arg = emu.arg(next_arg);
        next_arg += 1;
        let text = match conv {
            b's' if arg == 0 => "(null)".to_string(),
            b's' => String::from_utf8_lossy(&emu.read_cstr(arg, MAX_STRING, false)).to_string(),
            b'd' | b'i' => (arg as u32 as i32).to_string(),
            b'u' => (arg as u32).to_string(),
            b'x' => format!("{:x}", arg as u32),
            b'X' => format!("{:X}", arg as u32),
            b'o' => format!("{:o}", arg as u32),
            b'c' => ((arg as u8) as char).to_string(),
            _ => {
                // unsupported: emit the specifier as-is.
                String::from_utf8_lossy(&fmt[start..i]).to_string()
            }
        };

        let pad = width.saturating_sub(text.len());
        if left {
            out.extend(text.bytes());
            out.extend(std::iter::repeat(b' ').take(pad));
        } else {
            let fill = if zero_pad && conv != b's' { b'0' } else { b' ' };
            out.extend(std::iter::repeat(fill).take(pad));
            out.extend(text.bytes());
        }
    }

    if size > 0 {
        out.truncate(size - 1);
    }
    let n = out.len() as u64;
    out.push(0);
    let _ = emu.write_mem(buf, &out);
    Outcome::Return(n)
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("kernel32.VirtualAlloc"), "virtualalloc");
        assert_eq!(normalize("_malloc"), "malloc");
        assert_eq!(normalize("__security_check_cookie"), "security_check_cookie");
        assert_eq!(normalize("_HeapAlloc@12"), "heapalloc");
        assert_eq!(normalize("??2@YAPAXI@Z"), "??2@yapaxi@z");
        assert_eq!(normalize("msvcrt.memcpy"), "memcpy");
    }
}
