//! Tight strings: stack strings that are decoded in place by a tight loop.
//!
//! For each tight loop: explore the function until reaching the loop,
//! note the strings already on the stack, then run the loop
//! (with a budget) and look for new strings on the stack.
//!
//! This is FLOSS's `tightstrings.py`.
use std::collections::HashSet;

use lancelot::VA;

use crate::{
    driver::{self, Limits},
    emu::{CallPolicy, Emulator, ExecOptions},
    features::TightLoop,
    results::TightString,
    stackstrings::StackContext,
    strings,
    workspace::Workspace,
};

const MAX_INSN_COUNT: u64 = 10_000;
const MAX_ADDRESS_REVISITS: u32 = 300;

pub fn extract_tightstrings(
    _ws: &Workspace,
    emu: &mut Emulator,
    functions: &[(VA, Vec<TightLoop>)],
    min_length: usize,
) -> Vec<TightString> {
    let opts = ExecOptions {
        calls:      CallPolicy::StepOver,
        api_models: false,
        rep_max:    256,
    };
    let limits = Limits {
        max_insns: MAX_INSN_COUNT,
        max_hits:  MAX_ADDRESS_REVISITS,
    };

    let mut results = vec![];
    for (fva, loops) in functions {
        for tl in loops {
            emu.reset(*fva);
            let init_sp = emu.sp();

            if !driver::explore_to(emu, &opts, tl.start) {
                log::debug!("tightstrings: didn't reach loop at {:#x} in {fva:#x}", tl.start);
                continue;
            }

            // strings already on the stack before the loop runs aren't decoded by it.
            let before: HashSet<String> = match StackContext::capture(emu, tl.start, init_sp) {
                Some(ctx) => strings::extract_strings(&ctx.stack, min_length, &Default::default())
                    .into_iter()
                    .map(|s| s.string)
                    .collect(),
                None => Default::default(),
            };

            let end = driver::run_to(emu, &opts, tl.end, &limits, &mut driver::Nothing);
            log::debug!("tightstrings: loop at {:#x} in {fva:#x}: {end:?}", tl.start);

            if let Some(ctx) = StackContext::capture(emu, tl.start, init_sp) {
                results.extend(ctx.strings(*fva, min_length, &before, emu.pointer_size()));
            }
        }
    }
    results
}
