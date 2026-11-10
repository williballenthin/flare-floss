//! IDA Pro as a library (idalib): analyze a file into a database, or open an existing database,
//! read the program from it, and close it.
use std::{
    ffi::c_int,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use idalib::{
    idb::{IDBOpenOptions, IDB},
    meta::FileType,
};

use super::get_program;
use crate::program::{Arch, Program, VA};

/// like vivisect's shellcode workspaces.
const SHELLCODE_BASE_ADDRESS: VA = 0x690000;

// parts of the IDA SDK that idalib doesn't wrap. `ea_t` and `adiff_t` are 64 bits.
extern "C" {
    fn set_segment_addressing(ea: u64, bitness: usize) -> bool;
    fn setinf_flag(tag: c_int, flag: u32, value: bool) -> bool;
    fn rebase_program(delta: i64, flags: c_int) -> c_int;
    fn auto_mark_range(start: u64, end: u64, r#type: c_int);
}

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
