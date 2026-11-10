//! embed into the binary the data floss-rs needs at runtime, so it's one self-contained file:
//!
//!   - the SLEIGH specifications of x86, from open_sleigh (see `src/emu/sleigh.rs`),
//!   - FLOSS's FLIRT signatures, for the lancelot backend (see `src/backend/lancelot/flirt.rs`),
//!   - the table of Windows API calling conventions, which `build_apis.rs` generates.
//!
//! with the IDA backend, link to IDA, the one dynamic dependency (see `link_ida`).
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[path = "build_apis.rs"]
mod apis;

/// Link to IDA's libraries, via the stub libraries of the IDA SDK.
/// They're found, when floss-rs runs, in the IDA installation of this build (`$IDADIR`, or else
/// IDA's default installation directory), or along the library search path of the dynamic linker.
///
/// On macOS, they're weak libraries, so floss-rs also runs when IDA isn't there: see `backend::ida::is_loaded`.
#[cfg(feature = "ida")]
fn link_ida() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "macos" {
        idalib_build::configure_linkage()
            .expect("can't find IDA: set IDADIR to its installation directory");
        return;
    }

    let (install_path, _, _) = idalib_build::idalib_install_paths_with(false);
    let (_, stub_path, _, _) = idalib_build::idalib_sdk_paths();
    println!("cargo::rerun-if-env-changed=IDADIR");
    println!(
        "cargo::rustc-link-arg=-Wl,-rpath,{}",
        install_path.display()
    );
    println!(
        "cargo::rustc-link-arg=-Wl,-L{},-weak-lida,-weak-lidalib",
        stub_path.display()
    );
}

fn main() {
    #[cfg(feature = "ida")]
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
