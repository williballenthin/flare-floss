//! embed the SLEIGH specification files from `sleigh/x86` into the binary
//! (see `src/emu/sleigh.rs`), and generate the table of Windows API
//! calling conventions (see `build_apis.rs`).
use std::{env, fs, path::PathBuf};

#[path = "build_apis.rs"]
mod apis;

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    apis::generate(&root, &out_dir.join("apis-x86.tsv"));

    let dir = root.join("sleigh").join("x86");
    println!("cargo:rerun-if-changed={}", dir.display());

    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| !name.ends_with(".md"))
        .collect();
    names.sort();

    let mut src = String::from("pub static FILES: &[(&str, &[u8])] = &[\n");
    for name in names {
        src.push_str(&format!("    ({name:?}, include_bytes!({:?})),\n", dir.join(&name)));
    }
    src.push_str("];\n");

    fs::write(out_dir.join("sleigh_files.rs"), src).unwrap();
}
