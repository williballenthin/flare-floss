//! floss-rs as an IDA Pro plugin: the obfuscated strings of the open database (stack strings,
//! tight strings, and decoded strings) as synthetic strings. They are in the Strings window,
//! from the provider FLOSS, and in the listing, as comments where the program uses them.
//!
//! The plugin runs by itself, once for each database: when IDA's analysis of a new file is
//! complete, or when a database that it hasn't seen opens. The strings are stored in the
//! database. Edit > Plugins > FLOSS extracts them again.
//!
//! The program comes from the database (`floss::backend::ida::get_program`), which is read on
//! IDA's main thread. The analysis then works from that copy: it doesn't use IDA or change the
//! database, and IDA waits until it's done.
use std::{
    collections::HashSet,
    ffi::{c_int, c_void, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

use floss::results::ResultDocument;
use idalib::{plugin, xref::XRefQuery, IDAError, IDAPlugin, IDA, IDB};

mod sdk;
pub mod synth;

/// the synthetic string provider: an id from the range that IDA leaves to plugins.
const PROVIDER: u8 = 0x8F;
const PROVIDER_NAME: &CStr = c"FLOSS";

/// the netnode that marks a database whose strings were extracted.
const MARKER: &CStr = c"$ floss";

/// what IDA stores for one address is small, so when the strings there don't fit,
/// keep fewer of their related instructions: (uses, parts).
const RELATION_LIMITS: [(usize, usize); 4] = [(usize::MAX, usize::MAX), (usize::MAX, 16), (usize::MAX, 0), (0, 0)];

/// more text than IDA stores for one address.
const MAX_TEXT_AT_ADDRESS: usize = 4096;

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

/// The obfuscated strings of the database, and the static strings of the program's memory.
fn extract_strings(idb: &IDB) -> Result<(ResultDocument, HashSet<String>), IDAError> {
    let opts = floss::Options::default();
    let program = floss::backend::ida::get_program(idb).map_err(to_ida_error)?;
    let static_strings = program.segments.iter().flat_map(|s| synth::get_static_texts(&s.bytes, opts.min_length));
    let static_strings = static_strings.collect();
    Ok((floss::analyze(program, &opts).map_err(to_ida_error)?, static_strings))
}

struct Database<'a> {
    idb:            &'a IDB,
    static_strings: &'a HashSet<String>,
}

impl synth::Database for Database<'_> {
    fn get_function_start(&self, ea: u64) -> Option<u64> {
        self.idb.function_at(ea).map(|f| f.start_address())
    }

    fn is_mapped(&self, ea: u64) -> bool {
        self.idb.segment_at(ea).is_some()
    }

    fn get_instructions_referring_to(&self, ea: u64) -> Vec<u64> {
        let mut instructions = vec![];
        let mut xref = self.idb.first_xref_to(ea, XRefQuery::DATA);
        while let Some(x) = xref {
            if self.idb.flags_at(x.from()).is_code() {
                instructions.push(x.from());
            }
            xref = x.next_to();
        }
        instructions
    }

    fn has_static_string(&self, text: &str) -> bool {
        self.static_strings.contains(text)
    }
}

/// Replace the provider's synthetic strings with those for the strings that FLOSS found.
/// Returns how many are stored, and how many don't fit.
fn store_strings(db: &Database, doc: &ResultDocument) -> (usize, usize) {
    sdk::forget_strings(PROVIDER);
    let (mut stored, mut dropped) = (0, 0);
    for (ea, mut strings) in synth::get_synthetic_strings(&doc.strings, db) {
        let found = strings.len();
        let set = |strings: &[synth::SyntheticString]| {
            RELATION_LIMITS.iter().any(|&(uses, parts)| sdk::set_strings(PROVIDER, ea, strings, uses, parts))
        };

        let mut size = 0;
        let few = strings.iter().take_while(|s| {
            size += s.text.len();
            size <= MAX_TEXT_AT_ADDRESS
        });
        let few = few.count().max(1);
        strings.truncate(few);
        if !set(&strings) {
            // the most of the strings, from the first, that fit: `fit` of them do, and `over` don't.
            let (mut fit, mut over) = (0, strings.len());
            while over - fit > 1 {
                let middle = fit + (over - fit) / 2;
                if set(&strings[..middle]) {
                    fit = middle;
                } else {
                    over = middle;
                }
            }
            strings.truncate(fit);
            if !set(&strings) {
                strings.clear();
            }
        }
        stored += strings.len();
        dropped += found - strings.len();
    }
    (stored, dropped)
}

/// Extract the strings of the database and store them as synthetic strings.
fn run_floss(ida: &IDA, idb: &IDB) -> Result<(), IDAError> {
    let t0 = Instant::now();
    ida.msg("FLOSS: extracting obfuscated strings\n")?;

    // a panic that unwinds into IDA ends the process, and the work in the database with it.
    let (doc, static_strings) = catch_unwind(AssertUnwindSafe(|| extract_strings(idb))).unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("unknown");
        Err(IDAError::ffi_with(format!("floss-rs panicked: {message}")))
    })?;

    let db = Database {
        idb,
        static_strings: &static_strings,
    };
    let (stored, dropped) = store_strings(&db, &doc);
    sdk::has_netnode(MARKER, true);

    let strings = &doc.strings;
    let copies = strings.decoded_strings.iter().filter(|s| static_strings.contains(&s.string)).count();
    ida.msg(format!(
        "FLOSS: {} stack strings, {} tight strings, and {} decoded strings, as {stored} synthetic strings \
         in the Strings window, in {:.2}s\n",
        strings.stack_strings.len(),
        strings.tight_strings.len(),
        strings.decoded_strings.len(),
        t0.elapsed().as_secs_f64()
    ))?;
    if copies > 0 {
        ida.msg(format!("FLOSS: {copies} of the decoded strings are static strings of the program too, and aren't among them\n"))?;
    }
    if dropped > 0 {
        ida.msg(format!("FLOSS: {dropped} strings don't fit in the database next to the others at their address\n"))?;
    }
    Ok(())
}

/// Extract the strings, unless the database already has them.
fn run_floss_once(ida: &IDA, idb: &IDB) {
    if sdk::has_netnode(MARKER, false) {
        return;
    }
    if let Err(e) = run_floss(ida, idb) {
        let _ = ida.msg(format!("FLOSS: failed: {e}\n"));
    }
}

/// IDA's analysis of a new file is complete, so the functions to emulate are known.
extern "C" fn on_database_event(_user_data: *mut c_void, code: c_int, _va: *mut c_void) -> isize {
    if code == sdk::AUTO_EMPTY_FINALLY {
        if let Ok(idb) = IDB::current() {
            run_floss_once(&IDA::new(&idb), &idb);
        }
    }
    0
}

struct FlossPlugin;

#[plugin(
    name = "FLOSS",
    comment = "Extract obfuscated strings: stack strings, tight strings, and decoded strings",
    help = "Emulates the functions of the program to find the strings that it builds or decodes when it runs, \
            and stores them as synthetic strings: see the Strings window and the comments in the listing. \
            This runs by itself once for each database; run the plugin to extract the strings again."
)]
impl IDAPlugin for FlossPlugin {
    fn init(ida: &mut IDA, idb: &mut IDB) -> Result<Self, IDAError> {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Info);
        }
        sdk::register_provider(PROVIDER, PROVIDER_NAME);

        if sdk::is_analysis_complete() {
            run_floss_once(ida, idb);
        } else if !sdk::hook_database_events(on_database_event) {
            ida.msg("FLOSS: can't wait for the analysis to complete; run the plugin to extract the strings\n")?;
        }
        Ok(FlossPlugin)
    }

    fn run(&mut self, ida: &mut IDA, idb: &mut IDB, _arg: usize) -> Result<(), IDAError> {
        run_floss(ida, idb)
    }

    fn term(&mut self, _ida: &mut IDA, _idb: &mut IDB) -> Result<(), IDAError> {
        sdk::unhook_database_events(on_database_event);
        Ok(())
    }
}
