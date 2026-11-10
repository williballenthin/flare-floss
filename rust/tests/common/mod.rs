//! end-to-end tests that each program analysis backend runs: FLOSS finds the strings
//! hidden in the programs in `tests/programs`.
//! these cover cases that Python FLOSS misses; see the comments in each program's source.
//! (rebuild the binaries with `tests/programs/build.sh`.)
#![allow(dead_code)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use floss::{program::Program, results::ResultDocument};
use libtest_mimic::{Failed, Trial};

pub type Load = fn(&Path) -> anyhow::Result<Program>;

/// what FLOSS finds in each build of a program.
#[derive(Clone, Copy)]
enum Expected {
    /// this string, among the stack, tight, and decoded strings.
    String(&'static str),
    /// one decoded string with this text, from a call to the decoding routine,
    /// rather than from the emulation of its caller from the start.
    OneDecodedAtCall(&'static str),
}

const CASES: &[(&str, Expected)] = &[
    ("utf16-decode", Expected::String("hello wide world")),
    ("overlap-decode", Expected::String("secret password")),
    ("global-stackstring", Expected::String("C:\\malware.exe")),
    ("wide-stackstring", Expected::String("kernel32.dll")),
    ("inline-decode", Expected::String("http://evil.example")),
    ("reused-buffer", Expected::OneDecodedAtCall("secret key")),
];

pub fn get_program_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/programs/bin").join(name)
}

/// the path of a file among the test data of Python FLOSS, which is a git submodule.
pub fn get_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/data").join(name)
}

pub fn analyze(program: Program) -> Result<ResultDocument, Failed> {
    let opts = floss::Options {
        static_strings: false,
        ..Default::default()
    };
    Ok(floss::analyze(program, &opts).map_err(|e| format!("{e:#}"))?)
}

/// the stack, tight, and decoded strings.
pub fn get_strings(doc: &ResultDocument) -> BTreeSet<String> {
    let s = &doc.strings;
    s.stack_strings
        .iter()
        .chain(s.tight_strings.iter())
        .map(|s| s.string.clone())
        .chain(s.decoded_strings.iter().map(|s| s.string.clone()))
        .collect()
}

/// the calls that `passed_to` has for the strings with this text.
pub fn get_calls_that_take(doc: &ResultDocument, text: &str) -> BTreeSet<u64> {
    let s = &doc.strings;
    let stack = s.stack_strings.iter().chain(s.tight_strings.iter()).map(|s| (&s.string, &s.passed_to));
    let decoded = s.decoded_strings.iter().map(|s| (&s.string, &s.passed_to));
    let calls = stack.chain(decoded).filter(|(string, _)| string.contains(text));
    calls.flat_map(|(_, calls)| calls.iter().copied()).collect()
}

fn check(doc: &ResultDocument, expected: Expected) -> Result<(), Failed> {
    match expected {
        Expected::String(expected) => {
            let strings = get_strings(doc);
            if !strings.contains(expected) {
                return Err(format!("expected {expected:?}, found {strings:?}").into());
            }
        }
        Expected::OneDecodedAtCall(expected) => {
            let at_calls: Vec<_> = doc
                .strings
                .decoded_strings
                .iter()
                .filter(|s| s.decoded_at != s.decoding_routine && s.string.contains(expected))
                .map(|s| &s.string)
                .collect();
            if at_calls.len() != 1 {
                return Err(format!("expected one string with {expected:?}, found {at_calls:?}").into());
            }
        }
    }
    let (Expected::String(text) | Expected::OneDecodedAtCall(text)) = expected;
    if get_calls_that_take(doc, text).is_empty() {
        return Err(format!("expected a call that takes {text:?}: each program gives its string to OutputDebugString").into());
    }
    Ok(())
}

/// One trial for each build of each program, named `{backend}::strings::{program}::{file}`.
pub fn get_string_trials(backend: &str, load: Load) -> Vec<Trial> {
    let mut trials = vec![];
    for &(program, expected) in CASES {
        for arch in ["32", "64"] {
            for opt in ["O0", "O2"] {
                let file = format!("{program}-{arch}-{opt}.exe");
                let name = format!("{backend}::strings::{program}::{file}");
                trials.push(Trial::test(name, move || -> Result<(), Failed> {
                    let path = get_program_path(&file);
                    if !path.exists() {
                        return Err(format!("{file} doesn't exist: build it with tests/programs/build.sh").into());
                    }
                    let program = load(&path).map_err(|e| format!("{e:#}"))?;
                    check(&analyze(program)?, expected)
                }));
            }
        }
    }
    trials
}
