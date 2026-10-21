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
        }
    }
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
        let (stack_strings, global_strings) =
            stackstrings::extract_stackstrings(&ws, &mut emu, &functions, opts.min_length);
        doc.strings.stack_strings = stack_strings;
        decoded_elsewhere.extend(global_strings);
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
        let (tight_strings, decoded_strings) =
            tightstrings::extract_tightstrings(&ws, &mut emu, &functions, opts.min_length);
        doc.strings.tight_strings = tight_strings;
        decoded_elsewhere.extend(decoded_strings);
        doc.metadata.runtime.tight_strings = seconds(t);
    }

    if opts.decoded_strings {
        let t = Instant::now();
        let candidates = features::rank_decoding_functions(&features, opts.top_functions);
        let (decoded_strings, emulated) =
            decoded::decode_strings(&ws, &mut emu, &candidates, opts.time_budget, opts.min_length);
        doc.strings.decoded_strings = decoded_strings;
        doc.analysis.functions_analyzed_decoded_strings = emulated;
        doc.analysis.decoding_function_scores = candidates
            .required
            .iter()
            .chain(candidates.extra.iter())
            .take(emulated)
            .map(|va| (*va, features[va].score))
            .collect();
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
