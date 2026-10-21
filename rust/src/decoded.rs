//! Decoded strings: strings produced by decoding routines.
//!
//! For each candidate decoding routine (see `features`):
//!
//!   1. find the arguments it's called with: explore each function that calls it,
//!      and snapshot the emulator at each call to the routine;
//!   2. from each of those snapshots, run the routine (following calls,
//!      with a budget), and snapshot memory before each API call and at the end;
//!   3. look for strings in the memory that changed.
//!
//! This is FLOSS's `string_decoder.py`, `function_argument_getter.py`, and `decoding_manager.py`.
use std::collections::HashSet;

use lancelot::VA;

use crate::{
    driver::{self, Control, Limits, Observer},
    emu::{CallPolicy, Emulator, ExecOptions, Flow, Insn, MemoryView, Snapshot},
    results::{AddressType, DecodedString},
    strings,
    workspace::Workspace,
};

const MAX_INSN_COUNT: u64 = 20_000;
const MAX_ADDRESS_REVISITS: u32 = 300;

// when a routine is called from many places and decodes few strings,
// stop emulating it early.
const FUNCTION_MIN_DECODED_STRINGS: usize = 5;
const FUNCTION_CALLS_RARE: usize = 7;
const FUNCTION_CALLS_OFTEN: usize = 15;
const FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN: usize = 15;

/// The emulator state at a call to a decoding routine.
pub struct CallContext {
    /// the state with the program counter at the call instruction.
    pub state:          Snapshot,
    /// the call instruction.
    pub decoded_at:     VA,
    pub return_address: VA,
}

fn options() -> ExecOptions {
    ExecOptions {
        calls:      CallPolicy::StepOver,
        api_models: true,
        rep_max:    1024,
    }
}

/// Find the states at each call to the routine, by exploring its callers.
pub fn extract_call_contexts(ws: &Workspace, emu: &mut Emulator, routine: VA) -> Vec<CallContext> {
    struct CallMonitor {
        call_site: VA,
        contexts:  Vec<CallContext>,
    }

    impl Observer for CallMonitor {
        fn before(&mut self, emu: &mut Emulator, insn: &Insn) -> Control {
            if insn.va == self.call_site && insn.flow == Flow::Call {
                self.contexts.push(CallContext {
                    state:          emu.snapshot(),
                    decoded_at:     insn.va,
                    return_address: insn.next(),
                });
            }
            Control::Continue
        }
    }

    let call_sites: std::collections::BTreeSet<VA> = ws.callers(routine).collect();
    let mut contexts = vec![];
    for call_site in call_sites {
        let Some(caller) = ws.function_containing(call_site) else {
            continue;
        };
        if caller == routine {
            // ignore recursion.
            continue;
        }

        emu.reset(caller);
        let mut monitor = CallMonitor {
            call_site,
            contexts: vec![],
        };
        driver::explore(emu, &options(), &mut monitor);
        contexts.extend(monitor.contexts);
    }
    contexts
}

/// Collects memory views before each call to an API that isn't modeled.
///
/// Decoded strings are often passed to an API, like `CreateFileA` or `printf`,
/// and then freed or overwritten. The modeled APIs, like `memchr`, are
/// helpers used during decoding; snapshots there would show partially decoded strings.
struct DeltaCollector {
    views: Vec<MemoryView>,
}

impl Observer for DeltaCollector {
    fn before(&mut self, emu: &mut Emulator, insn: &Insn) -> Control {
        if insn.flow == Flow::Api && !emu.is_modeled_api(insn.va) {
            self.views.push(emu.memory());
        }
        Control::Continue
    }
}

/// Emulate the routine from the given call, returning memory before the call,
/// and memory at each API call and at the end.
fn emulate_decoding_routine(emu: &mut Emulator, ctx: &CallContext) -> (MemoryView, Vec<MemoryView>) {
    emu.restore(&ctx.state);
    let before = emu.memory();

    let mut collector = DeltaCollector { views: vec![] };
    let limits = Limits {
        max_insns: MAX_INSN_COUNT,
        max_hits:  MAX_ADDRESS_REVISITS,
    };
    let end = driver::run_to(emu, &options(), ctx.return_address, &limits, &mut collector);
    log::trace!("decoded: emulation from {:#x} ended: {end:?}", ctx.decoded_at);

    collector.views.push(emu.memory());
    (before, collector.views)
}

fn should_shortcut(n: usize, n_calls: usize, found_strings: usize) -> bool {
    let threshold = if n_calls < FUNCTION_CALLS_RARE {
        return false;
    } else if n_calls < FUNCTION_CALLS_OFTEN {
        n_calls / 2
    } else {
        FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN
    };
    n >= threshold && found_strings <= FUNCTION_MIN_DECODED_STRINGS
}

pub fn decode_strings(ws: &Workspace, emu: &mut Emulator, routines: &[VA], min_length: usize) -> Vec<DecodedString> {
    let mut results = vec![];
    for &routine in routines {
        let mut seen: HashSet<String> = ws.referenced_strings(routine);
        let contexts = extract_call_contexts(ws, emu, routine);
        let n_calls = contexts.len();
        log::debug!("decoded: routine {routine:#x}: {n_calls} calls");

        for (n, ctx) in contexts.iter().enumerate() {
            if should_shortcut(n + 1, n_calls, seen.len()) {
                log::debug!("decoded: shortcutting routine {routine:#x} after {n} calls");
                break;
            }

            let (before, afters) = emulate_decoding_routine(emu, ctx);
            for after in afters.iter() {
                for change in after.changes_since(&before) {
                    let address_type = AddressType::from(change.region);
                    for s in strings::extract_strings(&change.bytes, min_length, &seen) {
                        if !seen.insert(s.string.clone()) {
                            continue;
                        }
                        results.push(DecodedString {
                            address: change.va + s.offset as u64,
                            address_type,
                            string: s.string,
                            encoding: s.encoding,
                            decoded_at: ctx.decoded_at,
                            decoding_routine: routine,
                        });
                    }
                }
            }
        }
    }
    results
}
