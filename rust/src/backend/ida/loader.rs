//! IDA's libraries (libida and libidalib), which join the process only when IDA is there.
//!
//! One binary runs with IDA and without it, so the binary can't have the libraries
//! as ordinary dependencies: then it wouldn't start without them. Each platform has its own way:
//!
//!   - macOS: they're weak libraries (see `build.rs`). The dynamic linker loads them when the
//!     program starts, if it finds them. Otherwise the address of each of their symbols is null.
//!     The binary names no directory for them, so the dynamic linker finds them on its search path only.
//!   - Windows: they're delay-loaded DLLs (see `build.rs`). A call to one of their functions goes
//!     through a thunk of the linker, which loads the DLL the first time. `load_libraries` loads
//!     the DLLs before that, from IDA's directory. A variable can't have a thunk: the code reads
//!     its address from the pointer `__imp_<name>`, which is defined here, and set once the DLL is loaded.
//!   - Linux: the dynamic linker has neither, so the binary doesn't refer to the libraries at all.
//!     The functions of IDA that floss-rs calls are defined here: each one jumps to the address
//!     in its slot, which `load_libraries` sets, to the function in the library.
//!     The variables are defined here too, and exported (see `build.rs`), so the libraries
//!     use these instead of their own, as they do for a program that links to them.
//!
//! `load_libraries` finds IDA when floss-rs runs: see `find_and_load`. On macOS, the dynamic linker
//! has to find the libraries when the program starts, so there `load_libraries` starts the program
//! again, with IDA's directory on the dynamic linker's search path.
use std::{
    env,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{anyhow, Result};

/// Load IDA's libraries into this process, if they aren't there yet.
///
/// Nothing of IDA can be used before this succeeds.
///
/// On macOS, this replaces the process with a new one of the same program and arguments,
/// when IDA is installed and the dynamic linker didn't find it.
pub fn load_libraries() -> Result<()> {
    static LOADED: OnceLock<Result<(), String>> = OnceLock::new();
    LOADED
        .get_or_init(find_and_load)
        .clone()
        .map_err(|e| anyhow!(e))
}

/// Find IDA, and load its libraries: from `$IDADIR`, or else from the first of
/// `find_directories` that has them, or else from where the system searches for libraries.
///
/// IDA uses `$IDADIR` whatever the directory of its libraries, and ends the process
/// when that isn't an installation. So when `$IDADIR` is set, IDA is there or nowhere.
fn find_and_load() -> Result<(), String> {
    let has_ida = |directory: &Path| directory.join(platform::IDALIB).is_file();

    let directory = match env::var_os("IDADIR").filter(|d| !d.is_empty()).map(PathBuf::from) {
        Some(directory) if !has_ida(&directory) => {
            return Err(format!("IDA isn't in $IDADIR ({})", directory.display()));
        }
        Some(directory) => Some(directory),
        None => find_directories().into_iter().find(|d| has_ida(d)),
    };

    match directory {
        Some(directory) => {
            log::debug!("loading IDA's libraries from {}", directory.display());
            platform::load_from(Some(&directory))
                .map_err(|e| format!("IDA in {} can't be loaded: {e}", directory.display()))
        }
        None => platform::load_from(None).map_err(|e| {
            log::debug!("the system doesn't find IDA's libraries: {e}");
            format!("IDA's libraries ({} and {}) aren't found", platform::IDA, platform::IDALIB)
        }),
    }
}

/// The directories where IDA's libraries may be: in the default installation of `ida-config.json`
/// (which `hcli ida set-default` writes), and in the directory where IDA's installer puts it.
fn find_directories() -> Vec<PathBuf> {
    // IDA's user directory.
    let user = match env::var_os("IDAUSR") {
        Some(directories) => env::split_paths(&directories).next(),
        None if cfg!(windows) => {
            env::var_os("APPDATA").map(|d| PathBuf::from(d).join("Hex-Rays").join("IDA Pro"))
        }
        None => env::var_os("HOME").map(|d| PathBuf::from(d).join(".idapro")),
    };
    let configured = user
        .and_then(|user| std::fs::read_to_string(user.join("ida-config.json")).ok())
        .and_then(|config| parse_install_directory(&config));

    let default = if cfg!(windows) {
        env::var_os("ProgramFiles").map(|d| PathBuf::from(d).join("IDA Professional 9.5"))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from("/Applications/IDA Professional 9.5.app"))
    } else {
        env::var_os("HOME").map(|d| PathBuf::from(d).join("ida-pro-9.5"))
    };

    // on macOS, an installation is an application bundle, which has the libraries inside.
    let get_libraries = |installation: PathBuf| match cfg!(target_os = "macos") {
        true => installation.join("Contents").join("MacOS"),
        false => installation,
    };
    configured.into_iter().chain(default).map(get_libraries).collect()
}

/// The default installation of IDA, from the contents of `ida-config.json`.
fn parse_install_directory(config: &str) -> Option<PathBuf> {
    let config: serde_json::Value = serde_json::from_str(config).ok()?;
    let directory = config.get("Paths")?.get("ida-install-dir")?.as_str()?;
    (!directory.is_empty()).then(|| directory.into())
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        env,
        io::{self, Write},
        os::unix::process::CommandExt,
        path::{Path, PathBuf},
        process::Command,
    };

    pub const IDA: &str = "libida.dylib";
    pub const IDALIB: &str = "libidalib.dylib";

    /// the directories where the dynamic linker looks for a library that it didn't find elsewhere.
    const SEARCH_PATH: &str = "DYLD_FALLBACK_LIBRARY_PATH";
    /// the directories that the dynamic linker uses when the variable isn't set.
    const DEFAULT_SEARCH_PATH: &str = "/usr/local/lib:/usr/lib";

    /// Succeed when the dynamic linker found the libraries at the start of the program.
    ///
    /// Otherwise, when the libraries are in the directory, start the program again with the directory
    /// on the dynamic linker's search path. Then this doesn't return.
    pub fn load_from(directory: Option<&Path>) -> Result<(), String> {
        let init_library = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"init_library".as_ptr()) };
        if !init_library.is_null() {
            return Ok(());
        }
        let Some(directory) = directory else {
            return Err("the dynamic linker didn't find them".into());
        };

        let search_path = env::var_os(SEARCH_PATH).unwrap_or_else(|| DEFAULT_SEARCH_PATH.into());
        let mut directories: Vec<PathBuf> = env::split_paths(&search_path).collect();
        if directories.iter().any(|d| d == directory) {
            return Err("the dynamic linker searched the directory, and didn't load them".into());
        }
        directories.insert(0, directory.into());
        let search_path = env::join_paths(directories).map_err(|e| e.to_string())?;

        let program = env::current_exe().map_err(|e| e.to_string())?;
        let mut arguments = env::args_os();
        let mut command = Command::new(program);
        if let Some(name) = arguments.next() {
            command.arg0(name);
        }
        log::debug!("starting again, with IDA's libraries");
        let _ = io::stdout().flush();
        let error = command.args(arguments).env(SEARCH_PATH, search_path).exec();
        Err(format!("the program can't start again: {error}"))
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        ffi::{c_void, CStr, CString},
        os::unix::ffi::OsStrExt,
        path::Path,
        sync::atomic::{AtomicBool, AtomicPtr, Ordering},
    };

    pub const IDA: &str = "libida.so";
    pub const IDALIB: &str = "libidalib.so";

    #[cfg(target_arch = "x86_64")]
    macro_rules! assemble {
        ($($line:expr),* $(,)?) => { core::arch::global_asm!($($line),*, options(att_syntax)); };
    }
    #[cfg(target_arch = "x86_64")]
    macro_rules! jump_to_slot {
        () => {
            "jmp *2b(%rip)"
        };
    }

    #[cfg(target_arch = "aarch64")]
    macro_rules! assemble {
        ($($line:expr),* $(,)?) => { core::arch::global_asm!($($line),*); };
    }
    // x16 is the register that a procedure linkage table uses, too.
    #[cfg(target_arch = "aarch64")]
    macro_rules! jump_to_slot {
        () => {
            "adrp x16, 2b\nldr x16, [x16, :lo12:2b]\nbr x16"
        };
    }

    /// Define the functions of IDA: each has a slot, and jumps to the address in it.
    /// The slots are in the order of the names, from `floss_ida_slots`.
    macro_rules! define_functions {
        ($($name:ident)*) => {
            const FUNCTIONS: &[&CStr] = &[
                $(match CStr::from_bytes_with_nul(concat!(stringify!($name), "\0").as_bytes()) {
                    Ok(name) => name,
                    Err(_) => unreachable!(),
                }),*
            ];

            assemble!(
                ".pushsection .bss.floss_ida_slots,\"aw\",%nobits",
                ".balign 8",
                ".globl floss_ida_slots",
                ".hidden floss_ida_slots",
                "floss_ida_slots:",
                ".popsection",
                $(
                    ".pushsection .bss.floss_ida_slots,\"aw\",%nobits",
                    "2: .skip 8",
                    ".popsection",
                    concat!(".pushsection .text.floss_ida.", stringify!($name), ",\"ax\",%progbits"),
                    concat!(".globl ", stringify!($name)),
                    concat!(".hidden ", stringify!($name)),
                    concat!(".type ", stringify!($name), ",%function"),
                    concat!(stringify!($name), ":"),
                    jump_to_slot!(),
                    concat!(".size ", stringify!($name), ", .-", stringify!($name)),
                    ".popsection",
                )*
            );
        };
    }

    // every function of IDA that the binary refers to: idalib's, and those of the `extern` blocks here.
    // when the linker reports that a function of IDA is undefined, add it.
    define_functions! {
        auto_mark_range
        auto_wait
        close_database
        create_qflow_chart
        enable_console_messages
        enum_import_names
        fc_calc_block_type
        get_bytes
        get_current_config
        get_flags_ex
        get_func_name
        get_func_qty
        get_import_module_name
        get_import_module_qty
        get_license_manager
        get_ph
        get_segm_name
        get_segm_qty
        getinf
        getinf_buf
        getinf_flag
        getn_func
        getnseg
        init_database
        init_library
        interr
        is_debugger_on
        is_decompiler_available
        is_license_valid
        lock_func_range_ea
        lock_segment_by_ea
        next_head
        qalloc_or_throw
        qfree
        qvector_reserve
        rebase_program
        set_segment_addressing
        setinf_flag
    }

    extern "C" {
        static floss_ida_slots: [AtomicPtr<c_void>; FUNCTIONS.len()];
    }

    // the variables of IDA that the binary refers to: the SDK's `callui`, `batch`, and `under_debugger`.
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static callui: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static batch: AtomicBool = AtomicBool::new(false);
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static under_debugger: AtomicBool = AtomicBool::new(false);

    fn get_variables() -> [(&'static CStr, *mut u8, usize); 3] {
        [
            (c"callui", callui.as_ptr().cast(), size_of::<*mut c_void>()),
            (c"batch", batch.as_ptr().cast(), size_of::<bool>()),
            (c"under_debugger", under_debugger.as_ptr().cast(), size_of::<bool>()),
        ]
    }

    fn open(path: &Path) -> Result<*mut c_void, String> {
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let library = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if library.is_null() {
            let error = unsafe { CStr::from_ptr(libc::dlerror()) };
            return Err(error.to_string_lossy().into_owned());
        }
        Ok(library)
    }

    /// Share the variables with libida, like the dynamic linker does for a program that links to it:
    /// the library uses the variables of the program, which start with the values of its own.
    fn share_variables(ida: *mut c_void) -> Result<(), String> {
        for (name, ours, size) in get_variables() {
            let used = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
            if used.cast() != ours {
                return Err(format!("IDA doesn't use the variable {name:?} of floss-rs"));
            }
            let theirs: *const u8 = unsafe { libc::dlsym(ida, name.as_ptr()) }.cast();
            if theirs.is_null() {
                return Err(format!("IDA doesn't have the variable {name:?}"));
            }
            // SAFETY: both are variables of this size, and nothing else runs IDA's code yet.
            unsafe {
                if std::slice::from_raw_parts(ours, size).iter().all(|&b| b == 0) {
                    std::ptr::copy_nonoverlapping(theirs, ours, size);
                }
            }
        }
        Ok(())
    }

    /// Load the libraries from the directory, or else from where the dynamic linker searches.
    pub fn load_from(directory: Option<&Path>) -> Result<(), String> {
        let get_path = |name: &str| match directory {
            Some(directory) => directory.join(name),
            None => name.into(),
        };
        let ida = open(&get_path(IDA))?;
        share_variables(ida)?;
        let idalib = open(&get_path(IDALIB))?;

        for (name, slot) in FUNCTIONS.iter().zip(unsafe { &floss_ida_slots }) {
            // this finds the functions of libida too, which libidalib depends on.
            let function = unsafe { libc::dlsym(idalib, name.as_ptr()) };
            if function.is_null() {
                return Err(format!("IDA doesn't have the function {name:?}"));
            }
            slot.store(function, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use std::{
        env,
        ffi::{c_char, c_void, CStr},
        io,
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        sync::atomic::{AtomicPtr, Ordering},
    };

    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    pub const IDA: &str = "ida.dll";
    pub const IDALIB: &str = "idalib.dll";

    /// search for the dependencies of the DLL in its directory.
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x8;

    // the addresses of the variables of IDA that the binary refers to:
    // the SDK's `callui`, `batch`, and `under_debugger`.
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static __imp_callui: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static __imp_batch: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    #[no_mangle]
    #[allow(non_upper_case_globals)]
    static __imp_under_debugger: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

    fn open(path: &Path, flags: u32) -> Result<*mut c_void, String> {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let library = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), flags) };
        if library.is_null() {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(library)
    }

    /// Load the libraries from the directory, or else from where Windows searches: along `PATH`, among others.
    pub fn load_from(directory: Option<&Path>) -> Result<(), String> {
        let (ida, _idalib) = match directory {
            Some(directory) => {
                // LoadLibraryExW takes backslashes only.
                let directory: PathBuf = directory.components().collect();
                // IDA's plugins find the DLLs that they depend on along PATH.
                let path = env::var_os("PATH").unwrap_or_default();
                let directories = [directory.clone()].into_iter().chain(env::split_paths(&path));
                env::set_var("PATH", env::join_paths(directories).map_err(|e| e.to_string())?);
                (
                    open(&directory.join(IDA), LOAD_WITH_ALTERED_SEARCH_PATH)?,
                    open(&directory.join(IDALIB), LOAD_WITH_ALTERED_SEARCH_PATH)?,
                )
            }
            None => (open(Path::new(IDA), 0)?, open(Path::new(IDALIB), 0)?),
        };

        let variables: [(&CStr, &AtomicPtr<c_void>); 3] = [
            (c"callui", &__imp_callui),
            (c"batch", &__imp_batch),
            (c"under_debugger", &__imp_under_debugger),
        ];
        for (name, pointer) in variables {
            let variable = unsafe { GetProcAddress(ida, name.as_ptr()) };
            if variable.is_null() {
                return Err(format!("IDA doesn't have the variable {name:?}"));
            }
            pointer.store(variable, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_install_directory;

    #[test]
    fn the_default_installation_is_in_the_configuration() {
        assert_eq!(
            parse_install_directory(r#"{"Paths": {"ida-install-dir": "/opt/ida"}, "Version": 1}"#),
            Some(PathBuf::from("/opt/ida"))
        );
        // IDA writes an empty directory when it makes the file.
        assert_eq!(parse_install_directory(r#"{"Paths": {"ida-install-dir": ""}}"#), None);
        assert_eq!(parse_install_directory("{}"), None);
    }
}
