//! Program analysis via IDA Pro: whatever IDA loads, for x86 and x64.
//!
//! `get_program` reads an open database into a `Program`: the analyses and the emulator work
//! from the `Program`, not from the database. So the database is only used on the thread
//! that calls `get_program`, which is IDA's main thread.
//!
//! The feature `ida-database` is this much, for code that runs inside IDA, like a plugin.
//! The feature `ida` adds IDA as a library (idalib): `load` analyzes a file into a database,
//! or opens an existing one, reads the program, and closes the database.
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{c_char, c_int, c_uint, c_void, CStr},
};

use anyhow::{anyhow, bail, Result};
use idalib::{func::FunctionFlags, idb::IDB};

use crate::program::{Arch, BasicBlock, Function, Import, Program, Segment, VA};

#[cfg(feature = "ida")]
mod library;
#[cfg(feature = "ida")]
mod loader;
#[cfg(feature = "ida")]
pub use library::{find_input_file, is_database, load, validate_available, Options};

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

// parts of the IDA SDK that idalib doesn't wrap. `ea_t` and `uval_t` are 64 bits.
extern "C" {
    fn get_bytes(
        buf: *mut c_void,
        size: isize,
        ea: u64,
        gmb_flags: c_int,
        mask: *mut c_void,
    ) -> isize;
    fn is_debugger_on() -> bool;
    fn get_import_module_qty() -> c_uint;
    fn get_import_module_name(buf: *mut QString, mod_index: c_int) -> bool;
    fn enum_import_names(mod_index: c_int, callback: ImportCallback, param: *mut c_void) -> c_int;
    fn qfree(alloc: *mut c_void);
}

const GMB_READALL: c_int = 0x01;

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
