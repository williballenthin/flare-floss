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
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use lancelot::VA;

use crate::{
    driver::{self, Control, Limits, Observer},
    emu::{CallPolicy, Emulator, ExecOptions, Flow, Insn, MemoryView, Snapshot},
    features::Candidates,
    results::{AddressType, DecodedString, DecodingRoutine},
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
    /// the state with the program counter at the call instruction
    /// (or, when the routine has no callers, at the routine).
    pub state:          Snapshot,
    /// the call instruction (or, when the routine has no callers, the routine).
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
///
/// Each caller is explored once, collecting the state at every call to the routine;
/// the order of the contexts follows the order of the call sites.
pub fn extract_call_contexts(ws: &Workspace, emu: &mut Emulator, routine: VA) -> Vec<CallContext> {
    struct CallMonitor {
        call_sites: BTreeSet<VA>,
        contexts:   Vec<CallContext>,
    }

    impl Observer for CallMonitor {
        fn before(&mut self, emu: &mut Emulator, insn: &Insn) -> Control {
            if insn.flow == Flow::Call && self.call_sites.contains(&insn.va) {
                self.contexts.push(CallContext {
                    state:          emu.snapshot(),
                    decoded_at:     insn.va,
                    return_address: insn.next(),
                });
            }
            Control::Continue
        }
    }

    // call sites, grouped by the function that contains them.
    let mut callers: BTreeMap<VA, BTreeSet<VA>> = Default::default();
    for call_site in ws.callers(routine) {
        match ws.function_containing(call_site) {
            // ignore recursion.
            Some(caller) if caller != routine => {
                callers.entry(caller).or_default().insert(call_site);
            }
            _ => {}
        }
    }

    let mut contexts = vec![];
    if callers.is_empty() {
        // nothing calls the routine; it may be the entry point, an export, or a callback.
        // so emulate it as if it were called, with no particular arguments.
        let return_address = emu.reset_for_call(routine);
        contexts.push(CallContext {
            state: emu.snapshot(),
            decoded_at: routine,
            return_address,
        });
    }
    for (caller, call_sites) in callers {
        emu.reset(caller);
        let mut monitor = CallMonitor {
            call_sites,
            contexts: vec![],
        };
        driver::explore(emu, &options(), &mut monitor);
        contexts.extend(monitor.contexts);
    }
    contexts.sort_by_key(|ctx| ctx.decoded_at);
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

/// Once decoding has taken this long, start helper threads.
/// It's about what a helper's emulator takes to set up, so small files don't pay for helpers.
const HELPERS_AFTER: Duration = Duration::from_millis(300);

/// Emulate the candidate decoding routines and collect the strings they decode:
/// all the required candidates, then extra candidates until `budget` is spent.
/// Returns the strings, and the routines that were emulated, in the order of the candidates.
///
/// Routines are independent, so they can be emulated on several threads (each with its own
/// emulator), taking candidates in order from a shared queue.
pub fn decode_strings(
    ws: &Workspace,
    emu: &mut Emulator,
    candidates: &Candidates,
    budget: Duration,
    min_length: usize,
    threads: usize,
) -> (Vec<DecodedString>, Vec<DecodingRoutine>) {
    let t0 = Instant::now();
    let queue: Vec<(VA, bool)> = candidates
        .required
        .iter()
        .map(|&va| (va, true))
        .chain(candidates.extra.iter().map(|&va| (va, false)))
        .collect();
    let next = AtomicUsize::new(0);
    let done: Vec<Mutex<Option<(Vec<DecodedString>, DecodingRoutine)>>> = queue.iter().map(|_| Default::default()).collect();

    // the next candidate to emulate: required ones always, extra ones while there's time.
    let take = || -> Option<usize> {
        let i = next.fetch_add(1, Ordering::Relaxed);
        let &(_, required) = queue.get(i)?;
        if !required {
            let elapsed = t0.elapsed();
            if elapsed >= budget {
                return None;
            }
            if i == candidates.required.len() {
                log::info!(
                    "emulated the top {i} candidate decoding routines in {:.1}s; \
                     emulating more candidates, up to the {:.1}s time budget, for more thorough results",
                    elapsed.as_secs_f64(),
                    budget.as_secs_f64()
                );
            }
        }
        Some(i)
    };
    let decode = |emu: &mut Emulator, i: usize| {
        let (routine, required) = queue[i];
        let t = Instant::now();
        let (strings, calls) = decode_routine(ws, emu, routine, min_length);
        let f = &candidates.features[&routine];
        let report = DecodingRoutine {
            address: routine,
            score: f.score,
            floss_score: f.floss_score,
            required,
            calls,
            strings: strings.len(),
            seconds: t.elapsed().as_secs_f64(),
            features: f.summary(),
        };
        *done[i].lock().unwrap() = Some((strings, report));
    };

    let mut helpers_used = 0;
    std::thread::scope(|scope| {
        let mut helpers = vec![];
        while let Some(i) = take() {
            decode(emu, i);
            if helpers.is_empty() && threads > 1 && t0.elapsed() >= HELPERS_AFTER && next.load(Ordering::Relaxed) < queue.len() {
                helpers = (1..threads)
                    .map(|_| {
                        scope.spawn(|| -> anyhow::Result<crate::emu::Stats> {
                            let mut emu = Emulator::new(ws)?;
                            while let Some(i) = take() {
                                decode(&mut emu, i);
                            }
                            Ok(emu.stats)
                        })
                    })
                    .collect();
            }
        }
        helpers_used = helpers.len();
        for helper in helpers {
            match helper.join().expect("decoding thread panicked") {
                Ok(stats) => emu.stats.merge(&stats),
                Err(e) => log::warn!("decoding thread failed to start: {e}"),
            }
        }
    });

    let mut results = vec![];
    let mut routines = vec![];
    for (strings, report) in done.into_iter().filter_map(|d| d.into_inner().unwrap()) {
        results.extend(strings);
        routines.push(report);
    }
    if routines.len() > candidates.required.len() {
        let required = routines[..candidates.required.len()].iter().map(|r| r.strings).sum::<usize>();
        log::info!(
            "emulated {} of {} candidate decoding routines in {:.1}s{}; the extra routines decoded {} strings",
            routines.len(),
            queue.len(),
            t0.elapsed().as_secs_f64(),
            if helpers_used > 0 { format!(" with {} threads", helpers_used + 1) } else { String::new() },
            results.len() - required
        );
        if routines.len() < queue.len() {
            log::info!(
                "stopped at the {:.1}s time budget; a longer --time-budget emulates more of the candidates",
                budget.as_secs_f64()
            );
        }
    }

    (results, routines)
}

/// Emulate one candidate decoding routine from each of its call contexts.
/// Returns the strings, and the number of call contexts.
fn decode_routine(ws: &Workspace, emu: &mut Emulator, routine: VA, min_length: usize) -> (Vec<DecodedString>, usize) {
    let mut results = vec![];
    let mut seen: HashSet<String> = ws.referenced_strings(routine);
    // the decoded part of each string reported so far, and where it is.
    let mut seen_changed: HashSet<(VA, String)> = HashSet::new();
    let contexts = extract_call_contexts(ws, emu, routine);
    let n_calls = contexts.len();
    log::debug!("decoded: routine {routine:#x}: {n_calls} calls");
    for (n, ctx) in contexts.iter().enumerate() {
        if should_shortcut(n + 1, n_calls, seen.len()) {
            log::debug!("decoded: shortcutting routine {routine:#x} after {n} calls");
            break;
        }

        let (before, afters) = emulate_decoding_routine(emu, ctx);

        // the strings in each view, by address. a string that grows from one view
        // to the next, like one decoded a character at a time with an API call for each,
        // is reported once, as it is at the end.
        let mut found: Vec<strings::Written> = vec![];
        // the index in `found` of the latest string at each address.
        let mut latest: HashMap<VA, usize> = HashMap::new();
        for (i, after) in afters.iter().enumerate() {
            // only look at memory that changed since the previous view,
            // since strings elsewhere were already found.
            let previous = if i > 0 { Some(&afters[i - 1]) } else { None };
            let changes = after.changes_since(&before, previous);
            for w in strings::strings_touching(&before, after, &changes, min_length, &seen) {
                match latest.get(&w.va) {
                    Some(&i)
                        if found[i].string.encoding == w.string.encoding
                            && w.string.string.starts_with(&found[i].string.string) =>
                    {
                        found[i] = w;
                    }
                    _ => {
                        latest.insert(w.va, found.len());
                        found.push(w);
                    }
                }
            }
        }

        for w in found {
            // the same decoded characters, at the same place, but with different neighbors
            // than from an earlier call: these are leftovers from the call contexts,
            // like the rest of a reused buffer, so report only the first.
            if seen.contains(&w.string.string) || !seen_changed.insert(w.changed) {
                continue;
            }
            seen.insert(w.string.string.clone());
            results.push(DecodedString {
                address: w.va,
                address_type: AddressType::from(before.region(w.va)),
                string: w.string.string,
                encoding: w.string.encoding,
                decoded_at: ctx.decoded_at,
                decoding_routine: routine,
            });
        }
    }
    (results, n_calls)
}
