//! FLOSS, the FLARE Obfuscated String Solver, in Rust.
//!
//! The pieces, from the bottom up:
//!
//!   - `workspace`: the program, via lancelot: functions, blocks, imports, callers.
//!   - `emu`: an x86/x64 emulator (icicle) in a forgiving address space,
//!     with snapshots, memory diffs, and models of common APIs.
//!   - `driver`: strategies for running the emulator through code:
//!     explore all paths, or run to an address.
//!   - `strings`: finding strings in bytes, and filtering out junk.
//!   - the analyses, which combine the above:
//!     `stackstrings`, `tightstrings`, `features` (which functions to emulate),
//!     and `decoded` (emulate decoding routines).
use std::{path::PathBuf, time::Instant};

use anyhow::Result;

pub mod decoded;
pub mod driver;
pub mod emu;
pub mod features;
pub mod results;
pub mod stackstrings;
pub mod strings;
pub mod tightstrings;
pub mod workspace;

use results::{ResultDocument, StaticString};

/// The kind of input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pe,
    Shellcode32,
    Shellcode64,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub format:          Format,
    pub min_length:      usize,
    pub static_strings:  bool,
    pub stack_strings:   bool,
    pub tight_strings:   bool,
    pub decoded_strings: bool,
    /// FLIRT signature files, to recognize library functions.
    pub signatures:      Vec<PathBuf>,
    /// how many of the top-scoring candidate decoding routines to emulate, at least.
    pub top_functions:   usize,
    /// after those, keep emulating more candidates until decoding has taken this long.
    /// with zero, emulate exactly `top_functions` (plus tight functions), like FLOSS.
    pub time_budget:     std::time::Duration,
    /// only analyze these functions.
    pub functions:       Option<Vec<u64>>,
    /// threads for stack and tight string extraction.
    pub threads:         usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            format:          Format::Pe,
            min_length:      strings::MIN_LENGTH,
            static_strings:  true,
            stack_strings:   true,
            tight_strings:   true,
            decoded_strings: true,
            signatures:      vec![],
            top_functions:   20,
            time_budget:     std::time::Duration::from_secs(2),
            functions:       None,
            threads:         std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        }
    }
}

/// files with fewer functions than this don't use extra threads,
/// since each thread's emulator takes ~0.3s to set up.
const MIN_FUNCTIONS_PER_THREAD: usize = 500;

/// Apply `f` to chunks of `items`, in parallel, each thread with its own emulator
/// (icicle's VM can't be shared between threads). Results are in the order of `items`.
fn in_parallel<T: Sync, R: Send>(
    ws: &workspace::Workspace,
    emu: &mut emu::Emulator,
    items: &[T],
    threads: usize,
    f: impl Fn(&mut emu::Emulator, &[T]) -> R + Sync,
) -> Result<Vec<R>> {
    let threads = threads.min(items.len() / MIN_FUNCTIONS_PER_THREAD).max(1);
    if threads == 1 {
        return Ok(vec![f(emu, items)]);
    }

    // more chunks than threads, handed out as threads finish, since functions vary in cost.
    let chunks: Vec<&[T]> = items.chunks(items.len().div_ceil(threads * 8)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<R>>> = chunks.iter().map(|_| Default::default()).collect();
    log::debug!("using {threads} threads for {} items", items.len());

    let stats: Vec<emu::Stats> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| -> Result<emu::Stats> {
                    let mut emu = emu::Emulator::new(ws)?;
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(chunk) = chunks.get(i) else {
                            return Ok(emu.stats);
                        };
                        *results[i].lock().unwrap() = Some(f(&mut emu, chunk));
                    }
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().expect("worker panicked")).collect::<Result<_>>()
    })?;
    for s in stats {
        emu.stats.merge(&s);
    }

    Ok(results.into_iter().map(|r| r.into_inner().unwrap().expect("every chunk ran")).collect())
}

fn seconds(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1000.0).round() / 1000.0
}

pub fn analyze(buf: &[u8], opts: &Options) -> Result<ResultDocument> {
    let t0 = Instant::now();
    let mut doc = ResultDocument::default();
    doc.metadata.min_length = opts.min_length;

    if opts.static_strings {
        let t = Instant::now();
        doc.strings.static_strings = strings::extract_ascii_utf16(buf)
            .into_iter()
            .filter(|s| s.string.len() >= opts.min_length)
            .map(|s| StaticString {
                string:   s.string,
                offset:   s.offset as u64,
                encoding: s.encoding,
            })
            .collect();
        doc.metadata.runtime.static_strings = seconds(t);
    }

    if !(opts.stack_strings || opts.tight_strings || opts.decoded_strings) {
        doc.metadata.runtime.total = seconds(t0);
        return Ok(doc);
    }

    let t = Instant::now();
    let ws = match opts.format {
        Format::Pe => workspace::Workspace::from_pe(buf, &opts.signatures),
        Format::Shellcode32 => workspace::Workspace::from_shellcode(buf, lancelot::arch::Arch::X32),
        Format::Shellcode64 => workspace::Workspace::from_shellcode(buf, lancelot::arch::Arch::X64),
    };
    let ws = match ws {
        Ok(ws) => ws,
        Err(e) => {
            // like FLOSS, still report the static strings, such as for .NET assemblies.
            log::warn!("can't analyze the program, so only extracting static strings: {e}");
            doc.metadata.runtime.total = seconds(t0);
            return Ok(doc);
        }
    };
    let mut emu = emu::Emulator::new(&ws)?;
    doc.metadata.imagebase = ws.base_address();
    doc.analysis.functions_discovered = ws.functions().count();
    doc.analysis.functions_library = ws.functions().filter(|f| ws.is_library(f.va)).count();
    doc.metadata.runtime.workspace = seconds(t);

    let t = Instant::now();
    let mut features = features::find_decoding_function_features(&ws);
    if let Some(functions) = &opts.functions {
        features.retain(|va, _| functions.contains(va));
    }
    doc.metadata.runtime.find_features = seconds(t);

    // strings that the stack and tight string passes found in global memory or the heap;
    // they have addresses, like decoded strings, so they're reported with them.
    let mut decoded_elsewhere = vec![];
    if opts.stack_strings {
        let t = Instant::now();
        // functions with tight loops get tight string extraction instead,
        // which avoids reporting the encoded strings, too.
        let functions: Vec<u64> = features
            .values()
            .filter(|f| !opts.tight_strings || f.tight_loops().is_empty())
            .map(|f| f.va)
            .collect();
        doc.analysis.functions_analyzed_stack_strings = functions.len();
        for (stack_strings, global_strings) in in_parallel(&ws, &mut emu, &functions, opts.threads, |emu, chunk| {
            stackstrings::extract_stackstrings(&ws, emu, chunk, opts.min_length)
        })? {
            doc.strings.stack_strings.extend(stack_strings);
            decoded_elsewhere.extend(global_strings);
        }
        doc.metadata.runtime.stack_strings = seconds(t);
    }

    if opts.tight_strings {
        let t = Instant::now();
        let functions: Vec<(u64, Vec<features::TightLoop>)> = features
            .values()
            .filter(|f| !f.tight_loops().is_empty())
            .map(|f| (f.va, f.tight_loops()))
            .collect();
        doc.analysis.functions_analyzed_tight_strings = functions.len();
        for (tight_strings, decoded_strings) in in_parallel(&ws, &mut emu, &functions, opts.threads, |emu, chunk| {
            tightstrings::extract_tightstrings(&ws, emu, chunk, opts.min_length)
        })? {
            doc.strings.tight_strings.extend(tight_strings);
            decoded_elsewhere.extend(decoded_strings);
        }
        doc.metadata.runtime.tight_strings = seconds(t);
    }

    if opts.decoded_strings {
        let t = Instant::now();
        let candidates = features::rank_decoding_functions(&features, opts.top_functions);
        let (decoded_strings, routines) =
            decoded::decode_strings(&ws, &mut emu, &candidates, opts.time_budget, opts.min_length);
        doc.strings.decoded_strings = decoded_strings;
        doc.analysis.decoding_candidates = candidates.required.len() + candidates.extra.len();
        doc.analysis.functions_analyzed_decoded_strings = routines.len();
        doc.analysis.decoding_routines = routines;
        doc.metadata.runtime.decoded_strings = seconds(t);
    }

    let mut seen: std::collections::HashSet<String> =
        doc.strings.decoded_strings.iter().map(|s| s.string.clone()).collect();
    for s in decoded_elsewhere {
        if seen.insert(s.string.clone()) {
            doc.strings.decoded_strings.push(s);
        }
    }

    doc.metadata.emulation = emu.stats.clone();
    doc.metadata.runtime.total = seconds(t0);
    Ok(doc)
}
