//! end-to-end tests of floss-rs with the IDA backend.
//!
//! usage: `cargo test --release --test ida -- --test-threads=1`
//!
//! IDA only works on the main thread, with one database at a time, so this has its own
//! harness (libtest-mimic), which runs the trials one after another, on the main thread.
//! Each trial opens its own database, in a temporary directory, and closes it when it has the program.
use floss::{
    backend::ida,
    program::{Arch, Program},
};
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

fn load(path: &std::path::Path, opts: &ida::Options) -> Result<Program, Failed> {
    Ok(ida::load(path, opts).map_err(|e| format!("{e:#}"))?)
}

fn get_function_addresses(program: &Program) -> Vec<u64> {
    program.functions.iter().map(|f| f.va).collect()
}

fn main() {
    let mut args = Arguments::from_args();
    // the only number of threads that IDA works with: then libtest-mimic uses the main thread.
    args.test_threads = Some(1);

    if let Err(e) = ida::validate_available() {
        eprintln!("error: can't use IDA: {e:#}");
        std::process::exit(1);
    }
    idalib::enable_console_messages(false);

    let mut tests: Vec<Trial> = Vec::new();

    tests.push(Trial::test("idalib::smoke::open_binary", || {
        let program = load(&common::get_program_path("reused-buffer-32-O0.exe"), &Default::default())?;
        if program.functions.is_empty() {
            return Err(Failed::from("expected at least one function, got 0"));
        }
        if program.imports.is_empty() {
            return Err(Failed::from("expected at least one import, got 0"));
        }
        Ok(())
    }));

    tests.extend(common::get_string_trials("idalib", |path| ida::load(path, &Default::default())));

    tests.push(Trial::test("idalib::database::create_and_reopen", || {
        let dir = tempfile::tempdir()?;
        let sample = dir.path().join("sample.exe");
        std::fs::copy(common::get_program_path("reused-buffer-64-O2.exe"), &sample)?;
        let database = dir.path().join("sample.exe.i64");

        let opts = ida::Options {
            database: Some(database.clone()),
            ..Default::default()
        };
        let created = load(&sample, &opts)?;
        if !database.is_file() {
            return Err(Failed::from("the database isn't kept"));
        }
        let modified = std::fs::metadata(&database)?.modified()?;

        // with the database as an option, and then as the file to analyze.
        for reopened in [load(&sample, &opts)?, load(&database, &Default::default())?] {
            if get_function_addresses(&reopened) != get_function_addresses(&created) {
                return Err(Failed::from("the functions of the reopened database are different"));
            }
        }
        if std::fs::metadata(&database)?.modified()? != modified {
            return Err(Failed::from("the existing database is written to"));
        }
        if ida::find_input_file(&database) != Some(sample) {
            return Err(Failed::from("the file that the database was made from isn't found"));
        }
        Ok(())
    }));

    tests.push(Trial::test("idalib::database::temporary", || {
        let dir = tempfile::tempdir()?;
        let sample = dir.path().join("sample.exe");
        std::fs::copy(common::get_program_path("reused-buffer-64-O2.exe"), &sample)?;
        load(&sample, &Default::default())?;
        let files: Vec<_> = std::fs::read_dir(dir.path())?.map(|e| e.unwrap().file_name()).collect();
        if files != ["sample.exe"] {
            return Err(format!("IDA left files next to the sample: {files:?}").into());
        }
        Ok(())
    }));

    tests.push(Trial::test("idalib::shellcode::stack_strings", || {
        let path = common::get_data_path("src/shellcode-stackstrings/bin/shellcode-stackstrings.bin");
        if !path.is_file() {
            return Err(format!("{} doesn't exist", path.display()).into());
        }
        let opts = ida::Options {
            shellcode: Some(Arch::X32),
            ..Default::default()
        };
        let doc = common::analyze(load(&path, &opts)?)?;
        if doc.strings.stack_strings.is_empty() {
            return Err(Failed::from("expected stack strings, found none"));
        }
        Ok(())
    }));

    libtest_mimic::run(&args, tests).exit()
}
