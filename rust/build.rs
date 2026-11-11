//! embed into the binary the data floss-rs needs at runtime, so it's one self-contained file:
//!
//!   - the SLEIGH specifications of x86, from open_sleigh (see `src/emu/sleigh.rs`),
//!   - FLOSS's FLIRT signatures, for the lancelot backend (see `src/backend/lancelot/flirt.rs`),
//!   - the table of Windows API calling conventions, which `build_apis.rs` generates.
//!
//! with the IDA backend, link to IDA (see `link_ida`).
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[path = "build_apis.rs"]
mod apis;

/// Link to IDA's libraries, via the stub libraries of the IDA SDK, so the build needs no IDA.
///
/// With the feature `ida`, the binary also runs when IDA isn't there,
/// so the libraries aren't ordinary dependencies (see `backend::ida::loader`):
///
///   - macOS: they're weak libraries. The dynamic linker finds them in the IDA installation
///     of this build (`$IDADIR`, or else IDA's default installation directory),
///     or along its own search path.
///   - Windows: they're delay-loaded DLLs.
///   - Linux: the binary doesn't link to them. It exports the variables that it shares with them.
///
/// Without the feature `ida`, the code runs inside IDA, which has the libraries.
#[cfg(feature = "ida-database")]
fn link_ida() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let is_standalone = cfg!(feature = "ida");

    if os == "windows" {
        idalib_build::configure_idasdk_linkage();
        if is_standalone {
            for argument in ["/DELAYLOAD:ida.dll", "/DELAYLOAD:idalib.dll", "delayimp.lib"] {
                println!("cargo::rustc-link-arg={argument}");
            }
        }
        return;
    }

    if os == "linux" && is_standalone {
        // on a machine without IDA, idalib's build script adds the stub libraries to this link.
        // these linker scripts have the same names and no content, and the linker finds them first.
        let directory = PathBuf::from(env::var("OUT_DIR").unwrap()).join("ida");
        fs::create_dir_all(&directory).unwrap();
        for library in ["libida.so", "libidalib.so"] {
            fs::write(directory.join(library), "/* no libraries */\n").unwrap();
        }
        println!("cargo::rustc-link-search=native={}", directory.display());

        for variable in ["callui", "batch", "under_debugger"] {
            println!("cargo::rustc-link-arg=-Wl,--export-dynamic-symbol={variable}");
        }
        return;
    }

    let (install_path, _, _) = idalib_build::idalib_install_paths_with(false);
    let (_, stub_path, _, _) = idalib_build::idalib_sdk_paths();
    let libraries = if os == "macos" {
        "-weak-lida,-weak-lidalib"
    } else {
        "-l:libida.so,-l:libidalib.so"
    };
    println!("cargo::rerun-if-env-changed=IDADIR");
    println!(
        "cargo::rustc-link-arg=-Wl,-rpath,{}",
        install_path.display()
    );
    println!(
        "cargo::rustc-link-arg=-Wl,-L{},{libraries}",
        stub_path.display()
    );
}

fn main() {
    #[cfg(feature = "ida-database")]
    link_ida();

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // the git submodules in deps/ are empty directories until they're checked out.
    for submodule in ["open_sleigh", "win32json", "phnt"] {
        let checked_out = fs::read_dir(root.join("deps").join(submodule)).is_ok_and(|mut d| d.next().is_some());
        if !checked_out {
            panic!("deps/{submodule} is missing: run `git submodule update --init rust/deps`");
        }
    }

    apis::generate(&root, &out_dir.join("apis-x86.tsv"));

    // what icicle reads: language definitions, processor and compiler specifications, and SLEIGH.
    embed(
        &root.join("deps").join("open_sleigh").join("src").join("x86"),
        &["ldefs", "pspec", "cspec", "slaspec", "sinc"],
        "include_str",
        &out_dir.join("sleigh_files.rs"),
    );

    #[cfg(feature = "lancelot")]
    embed(
        &root.join("..").join("floss").join("sigs"),
        &["sig", "pat"],
        "include_bytes",
        &out_dir.join("flirt_files.rs"),
    );
}

/// write `out`, Rust source for `FILES`: the name and contents of each file in `dir`
/// with one of the `extensions`, included with `include` (`include_str` or `include_bytes`).
fn embed(dir: &Path, extensions: &[&str], include: &str, out: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| extensions.iter().any(|e| name.ends_with(&format!(".{e}"))))
        .collect();
    names.sort();

    let ty = if include == "include_str" { "&str" } else { "&[u8]" };
    let mut src = format!("pub static FILES: &[(&str, {ty})] = &[\n");
    for name in names {
        src.push_str(&format!("    ({name:?}, {include}!({:?})),\n", dir.join(&name)));
    }
    src.push_str("];\n");
    fs::write(out, src).unwrap();
}
