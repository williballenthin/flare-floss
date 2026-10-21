//! embed the SLEIGH specification files from `sleigh/x86` into the binary.
//! see `src/emu/sleigh.rs`.
use std::{env, fs, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("sleigh").join("x86");
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

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("sleigh_files.rs");
    fs::write(out, src).unwrap();
}
