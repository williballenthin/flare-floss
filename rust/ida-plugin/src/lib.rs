//! floss-rs as an IDA Pro plugin: Edit > Plugins > FLOSS extracts the obfuscated strings of the
//! open database (stack strings, tight strings, and decoded strings), and prints them to the
//! output window, each after an address to jump to.
//!
//! The program comes from the database (`floss::backend::ida::get_program`), which is read on
//! IDA's main thread. The analysis then works from that copy: it doesn't use IDA or change the
//! database, and IDA waits until it's done.
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

use floss::results::ResultDocument;
use idalib::{plugin, IDAError, IDAPlugin, IDA, IDB};

/// floss-rs's log messages, like its progress through the candidate decoding routines,
/// go to the output window.
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info && metadata.target().starts_with("floss")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // SAFETY: IDA's `msg` can be called from any thread, and floss-rs logs from its own.
            let _ = unsafe { idalib::ffi::ida::msg(format!("FLOSS: {}\n", record.args())) };
        }
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

fn to_ida_error(e: impl std::fmt::Display) -> IDAError {
    IDAError::ffi_with(format!("{e:#}"))
}

fn extract_strings(idb: &IDB) -> Result<ResultDocument, IDAError> {
    let program = floss::backend::ida::get_program(idb).map_err(to_ida_error)?;
    floss::analyze(program, &floss::Options::default()).map_err(to_ida_error)
}

/// The lines for the output window: IDA jumps to an address there with a double click.
fn render_strings(doc: &ResultDocument) -> Vec<String> {
    let strings = &doc.strings;
    let sections: [(&str, Vec<(u64, &str)>); 3] = [
        ("STACK", strings.stack_strings.iter().map(|s| (s.program_counter, s.string.as_str())).collect()),
        ("TIGHT", strings.tight_strings.iter().map(|s| (s.program_counter, s.string.as_str())).collect()),
        ("DECODED", strings.decoded_strings.iter().map(|s| (s.decoded_at, s.string.as_str())).collect()),
    ];

    let mut lines = vec![];
    for (name, strings) in sections {
        lines.push(format!("FLOSS {name} STRINGS ({})", strings.len()));
        lines.extend(strings.into_iter().map(|(va, string)| format!("{va:#x}: {string}")));
    }
    lines
}

struct FlossPlugin;

#[plugin(
    name = "FLOSS",
    comment = "Extract obfuscated strings: stack strings, tight strings, and decoded strings",
    help = "Emulates the functions of the program to find the strings that it builds or decodes when it runs, \
            and prints them to the output window."
)]
impl IDAPlugin for FlossPlugin {
    fn init(_ida: &mut IDA, _idb: &mut IDB) -> Result<Self, IDAError> {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Info);
        }
        Ok(FlossPlugin)
    }

    fn run(&mut self, ida: &mut IDA, idb: &mut IDB, _arg: usize) -> Result<(), IDAError> {
        let t0 = Instant::now();
        ida.msg("FLOSS: extracting obfuscated strings\n")?;

        // a panic that unwinds into IDA ends the process, and the work in the database with it.
        let doc = catch_unwind(AssertUnwindSafe(|| extract_strings(idb))).unwrap_or_else(|panic| {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown");
            Err(IDAError::ffi_with(format!("floss-rs panicked: {message}")))
        })?;

        for line in render_strings(&doc) {
            ida.msg(format!("{line}\n"))?;
        }
        ida.msg(format!("FLOSS: finished in {:.2}s\n", t0.elapsed().as_secs_f64()))
    }
}
