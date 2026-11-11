//! Run the plugin inside IDA, on floss-rs's test programs, and check the synthetic strings that it stores.
//!
//! IDA is `idat`, the text-mode IDA of the installation that the plugin is built for. It loads
//! the plugin by itself, from a plugins directory of the test's own, and analyzes a copy of the
//! program; the plugin runs when that's done. Then an IDAPython script prints the synthetic
//! strings of the database, and the listing at their uses, to IDA's log file.
use std::{
    env::consts::{DLL_PREFIX, DLL_SUFFIX, EXE_SUFFIX},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MANIFEST: &str = include_str!("../ida-plugin.json");

const DUMP: &str = r#"
import ida_auto, ida_ida, ida_lines, ida_pro, ida_strlist

ida_auto.auto_wait()
strings = ida_strlist.synth_strings_t()
ida_strlist.synth_string_get_range(strings, ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
for s in strings:
    provider = ida_strlist.synth_string_provider_name(s.provider)
    print("SYNTH %x|%s|%s|%s" % (s.ea, provider, ",".join("%x" % use for use in s.uses), s.text))
    for ea in set(s.uses) | {s.ea}:
        for line in ida_lines.generate_disassembly(ea, 8, False, True)[1]:
            print("LINE %x|%s" % (ea, line))
ida_pro.qexit(0)
"#;

#[derive(Debug, PartialEq)]
struct SyntheticString {
    ea:       u64,
    provider: String,
    uses:     Vec<u64>,
    text:     String,
}

/// What IDA's log has after it opened a file with the plugin.
struct Database {
    log: String,
}

impl Database {
    fn strings(&self) -> Vec<SyntheticString> {
        let parse = |line: &str| -> Option<SyntheticString> {
            let mut fields = line.strip_prefix("SYNTH ")?.splitn(4, '|');
            Some(SyntheticString {
                ea:       u64::from_str_radix(fields.next()?, 16).ok()?,
                provider: fields.next()?.to_string(),
                uses:     fields.next()?.split(',').filter_map(|use_| u64::from_str_radix(use_, 16).ok()).collect(),
                text:     fields.next()?.to_string(),
            })
        };
        self.log.lines().filter_map(parse).collect()
    }

    fn string(&self, text: &str) -> SyntheticString {
        let strings = self.strings();
        let found = strings.into_iter().find(|s| s.text == text);
        found.unwrap_or_else(|| panic!("no synthetic string {text:?}:\n{}", self.log))
    }

    /// the listing at an address: the instruction or data there, with its comments.
    fn listing(&self, ea: u64) -> String {
        let prefix = format!("LINE {ea:x}|");
        self.log.lines().filter_map(|line| line.strip_prefix(&prefix)).collect::<Vec<_>>().join("\n")
    }

    fn ran_floss(&self) -> bool {
        self.log.contains("FLOSS: extracting obfuscated strings")
    }
}

/// A directory with a copy of one of the test programs, for IDA to make its database in.
fn get_workspace(program: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let sample = dir.path().join(program);
    let programs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/programs/bin");
    std::fs::copy(programs.join(program), &sample).unwrap();
    (dir, sample)
}

/// Open a program or a database in IDA, with the plugin among IDA's plugins.
fn open(dir: &Path, input: &Path) -> Database {
    // cargo puts the plugin next to this test.
    let name = format!("{DLL_PREFIX}floss_ida{DLL_SUFFIX}");
    let plugin = std::env::current_exe().unwrap().with_file_name(&name);
    assert!(plugin.exists(), "the plugin isn't built: {}", plugin.display());
    let idat = Path::new(env!("IDADIR")).join(format!("idat{EXE_SUFFIX}"));

    // IDA loads plugins from each user directory; the license is in the user's own.
    // the plugin is there as the Plugin Manager installs it: a directory with ida-plugin.json,
    // and the library by the name of the entry point.
    let user = dir.join("user");
    let installed = user.join("plugins").join("floss");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(installed.join("ida-plugin.json"), MANIFEST).unwrap();
    std::fs::copy(&plugin, installed.join(format!("floss_ida{DLL_SUFFIX}"))).unwrap();
    let home = if cfg!(windows) {
        std::env::var_os("APPDATA").map(|appdata| PathBuf::from(appdata).join("Hex-Rays").join("IDA Pro"))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".idapro"))
    };
    let users = std::env::var_os("IDAUSR").map(|users| std::env::split_paths(&users).collect()).or(home.map(|home| vec![home]));
    let users = std::env::join_paths([user].into_iter().chain(users.unwrap_or_default())).unwrap();

    let script = dir.join("dump.py");
    std::fs::write(&script, DUMP).unwrap();
    let log = dir.join("ida.log");
    let _ = std::fs::remove_file(&log);

    let status = Command::new(&idat)
        .arg("-A")
        .arg(format!("-L{}", log.display()))
        .arg(format!("-S{}", script.display()))
        .arg(input)
        .env("TVHEADLESS", "1")
        .env("IDAUSR", users)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("can't run {}: {e}", idat.display()));
    let log = String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default()).into_owned();
    assert!(status.success(), "IDA failed ({status}):\n{log}");
    Database { log }
}

fn analyze(program: &str) -> Database {
    let (dir, sample) = get_workspace(program);
    open(dir.path(), &sample)
}

#[test]
fn manifest_has_the_version_of_the_crate() {
    let version = concat!("\"version\": \"", env!("CARGO_PKG_VERSION"), "\"");
    assert!(MANIFEST.contains(version), "ida-plugin.json doesn't have {version}");
}

#[test]
fn stack_string_shows_at_the_call_that_takes_it() {
    let db = analyze("wide-stackstring-64-O2.exe");
    assert!(db.ran_floss());

    let string = db.string("kernel32.dll");
    assert_eq!(string.provider, "FLOSS");
    assert!(db.listing(string.ea).contains("mov"), "the string is at an instruction that wrote it:\n{}", db.log);
    assert!(!db.listing(string.ea).contains("\"kernel32.dll\""));

    let [use_] = string.uses[..] else { panic!("one use: {string:?}") };
    let listing = db.listing(use_);
    assert!(listing.contains("call") && listing.contains("\"kernel32.dll\""), "{listing}");
}

#[test]
fn decoded_strings_show_at_the_call_that_decodes_them_and_at_their_uses() {
    let db = analyze("reused-buffer-32-O0.exe");

    let string = db.string("secret key-xyz");
    assert!(db.listing(string.ea).contains("call"), "the string is at the call that decoded it:\n{}", db.log);
    assert!(string.uses.len() > 1 && string.uses.contains(&string.ea), "{string:?}");
    for use_ in &string.uses {
        assert!(db.listing(*use_).contains("\"secret key-xyz\""), "{}", db.listing(*use_));
    }

    let string = db.string("secret key+abc");
    assert!(string.uses.iter().all(|use_| db.listing(*use_).contains("\"secret key+abc\"")), "{}", db.log);
    assert_eq!(db.strings().len(), 2, "{}", db.log);
}

#[test]
fn global_string_shows_at_the_instructions_that_refer_to_it() {
    let db = analyze("global-stackstring-64-O0.exe");

    let string = db.string("C:\\malware.exe");
    assert_eq!(string.ea, 0x140003000);
    assert!(!string.uses.is_empty());
    for use_ in &string.uses {
        assert!(db.listing(*use_).contains(r#""C:\\malware.exe""#), "{}", db.listing(*use_));
    }
    let arguments = string.uses.iter().filter(|use_| db.listing(**use_).contains("lpOutputString"));
    assert!(arguments.count() > 0, "next to the comment that IDA has there for the argument:\n{}", db.log);
}

#[test]
fn strings_stay_in_the_database() {
    let (dir, sample) = get_workspace("wide-stackstring-64-O2.exe");
    let first = open(dir.path(), &sample);
    assert!(first.ran_floss());

    let database = sample.with_file_name("wide-stackstring-64-O2.exe.i64");
    assert!(database.exists(), "IDA saved its database:\n{}", first.log);
    let second = open(dir.path(), &database);
    assert!(!second.ran_floss(), "the database has its strings already:\n{}", second.log);
    assert_eq!(first.strings(), second.strings());
    assert_eq!(second.string("kernel32.dll").provider, "FLOSS");
}
