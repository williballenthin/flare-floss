//! end-to-end tests: FLOSS finds the strings hidden in the programs in `tests/programs`.
//! these cover cases that Python FLOSS misses; see the comments in each program's source.
//! (rebuild the binaries with `tests/programs/build.sh`.)
use std::collections::BTreeSet;

fn found(name: &str) -> BTreeSet<String> {
    let path = format!("{}/tests/programs/bin/{name}", env!("CARGO_MANIFEST_DIR"));
    let buf = std::fs::read(&path).unwrap();
    let opts = floss::Options {
        static_strings: false,
        ..Default::default()
    };
    let doc = floss::analyze(&buf, &opts).unwrap();
    let s = doc.strings;
    s.stack_strings
        .iter()
        .chain(s.tight_strings.iter())
        .map(|s| s.string.clone())
        .chain(s.decoded_strings.iter().map(|s| s.string.clone()))
        .collect()
}

fn check(program: &str, expected: &str) {
    for arch in ["32", "64"] {
        for opt in ["O0", "O2"] {
            let name = format!("{program}-{arch}-{opt}.exe");
            let strings = found(&name);
            assert!(strings.contains(expected), "{name}: expected {expected:?}, found {strings:?}");
        }
    }
}

#[test]
fn utf16_decode() {
    check("utf16-decode", "hello wide world");
}

#[test]
fn overlap_decode() {
    check("overlap-decode", "secret password");
}

#[test]
fn global_stackstring() {
    check("global-stackstring", "C:\\malware.exe");
}

#[test]
fn wide_stackstring() {
    check("wide-stackstring", "kernel32.dll");
}

#[test]
fn inline_decode() {
    check("inline-decode", "http://evil.example");
}
