//! Run the plugin inside IDA, on floss-rs's test programs, and check the strings that it prints.
//!
//! IDA is `idat`, the text-mode IDA of the installation that the plugin is built for.
//! It analyzes a copy of the program, runs the plugin from an IDC script, and exits;
//! what the plugin prints to the output window is in IDA's log file.
use std::{
    env::consts::{DLL_PREFIX, DLL_SUFFIX, EXE_SUFFIX},
    path::Path,
    process::{Command, Stdio},
};

/// The lines that the plugin prints for one of the test programs.
fn run_plugin(program: &str) -> Vec<String> {
    // cargo puts the plugin next to this test.
    let plugin = std::env::current_exe().unwrap().with_file_name(format!("{DLL_PREFIX}floss_ida{DLL_SUFFIX}"));
    assert!(plugin.exists(), "the plugin isn't built: {}", plugin.display());
    let idat = Path::new(env!("IDADIR")).join(format!("idat{EXE_SUFFIX}"));

    // IDA makes its database next to the program.
    let dir = tempfile::tempdir().unwrap();
    let sample = dir.path().join(program);
    let programs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/programs/bin");
    std::fs::copy(programs.join(program), &sample).unwrap();

    let script = dir.path().join("run.idc");
    std::fs::write(
        &script,
        format!(
            "static main() {{ auto_wait(); qexit(load_and_run_plugin({:?}, 0) ? 0 : 1); }}",
            plugin.to_str().unwrap()
        ),
    )
    .unwrap();

    let log = dir.path().join("ida.log");
    let status = Command::new(&idat)
        .arg("-A")
        .arg(format!("-L{}", log.display()))
        .arg(format!("-S{}", script.display()))
        .arg(&sample)
        .env("TVHEADLESS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("can't run {}: {e}", idat.display()));
    let log = String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default()).into_owned();
    assert!(status.success(), "IDA failed ({status}):\n{log}");

    log.lines()
        .skip_while(|line| !line.starts_with("FLOSS"))
        .map(String::from)
        .collect()
}

/// The strings in a section of the plugin's output, like `STACK`, each with its address.
fn get_strings(lines: &[String], section: &str) -> Vec<(u64, String)> {
    lines
        .iter()
        .skip_while(|line| !line.starts_with(&format!("FLOSS {section} STRINGS (")))
        .skip(1)
        .map_while(|line| {
            let (va, string) = line.strip_prefix("0x")?.split_once(": ")?;
            Some((u64::from_str_radix(va, 16).ok()?, string.to_string()))
        })
        .collect()
}

#[test]
fn stack_string() {
    let lines = run_plugin("wide-stackstring-64-O2.exe");
    let strings = get_strings(&lines, "STACK");
    assert!(
        strings.iter().any(|(va, string)| string == "kernel32.dll" && *va >= 0x140001000),
        "no stack string kernel32.dll, at an address in the program:\n{}",
        lines.join("\n")
    );
    assert!(lines.iter().any(|line| line.starts_with("FLOSS: finished in ")));
}

#[test]
fn decoded_strings() {
    let lines = run_plugin("reused-buffer-32-O0.exe");
    let strings = get_strings(&lines, "DECODED");
    for expected in ["secret key-xyz", "secret key+abc"] {
        assert!(
            strings.iter().any(|(va, string)| string == expected && *va >= 0x401000),
            "no decoded string {expected}, at an address in the program:\n{}",
            lines.join("\n")
        );
    }
    assert!(get_strings(&lines, "STACK").is_empty());
}
