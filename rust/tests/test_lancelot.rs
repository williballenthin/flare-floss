//! end-to-end tests of floss-rs with the lancelot backend.
//!
//! usage: `cargo test --release --test lancelot`
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

fn main() {
    let args = Arguments::from_args();

    let mut tests = common::get_string_trials("lancelot", |path| {
        floss::backend::lancelot::load_pe(&std::fs::read(path)?, &[])
    });

    tests.push(Trial::test("lancelot::shellcode::stack_strings", || -> Result<(), Failed> {
        let path = common::get_data_path("src/shellcode-stackstrings/bin/shellcode-stackstrings.bin");
        let buf = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let program =
            floss::backend::lancelot::load_shellcode(&buf, floss::program::Arch::X32).map_err(|e| format!("{e:#}"))?;
        let doc = common::analyze(program)?;
        if doc.strings.stack_strings.is_empty() {
            return Err("expected stack strings, found none".into());
        }
        Ok(())
    }));

    libtest_mimic::run(&args, tests).exit()
}
