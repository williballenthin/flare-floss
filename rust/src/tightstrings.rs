//! Tight strings: stack strings that are decoded in place by a tight loop.
//!
//! For each tight loop: explore the function until reaching the loop,
//! then run the loop (with a budget), and look for strings in the memory it wrote.
//!
//! This is like FLOSS's `tightstrings.py`, which looks for strings on the stack
//! after the loop that weren't there before it. Diffing memory finds those too,
//! plus strings the loop decodes into global memory or the heap.
use lancelot::VA;

use crate::{
    driver::{self, Limits},
    emu::{snapshot::Region, CallPolicy, Emulator, ExecOptions},
    features::TightLoop,
    results::{AddressType, DecodedString, TightString},
    strings,
    workspace::Workspace,
};

const MAX_INSN_COUNT: u64 = 10_000;
const MAX_ADDRESS_REVISITS: u32 = 300;

pub fn extract_tightstrings(
    ws: &Workspace,
    emu: &mut Emulator,
    functions: &[(VA, Vec<TightLoop>)],
    min_length: usize,
) -> (Vec<TightString>, Vec<DecodedString>) {
    let opts = ExecOptions {
        calls:      CallPolicy::StepOver,
        api_models: false,
        rep_max:    256,
    };
    let limits = Limits {
        max_insns: MAX_INSN_COUNT,
        max_hits:  MAX_ADDRESS_REVISITS,
    };

    let mut tight = vec![];
    let mut decoded = vec![];
    for (fva, loops) in functions {
        let mut seen = ws.referenced_strings(*fva);
        for tl in loops {
            emu.reset(*fva);
            let init_sp = emu.sp();

            if !driver::explore_to(emu, &opts, tl.start) {
                log::debug!("tightstrings: didn't reach loop at {:#x} in {fva:#x}", tl.start);
                continue;
            }

            let before = emu.memory();
            let end = driver::run_to(emu, &opts, tl.end, &limits, &mut driver::Nothing);
            log::debug!("tightstrings: loop at {:#x} in {fva:#x}: {end:?}", tl.start);
            let after = emu.memory();
            let sp = emu.sp();

            // the strings the loop wrote to: on the stack, these are tight strings;
            // elsewhere (which FLOSS doesn't look for), they're decoded strings.
            for change in after.changes_since(&before, None) {
                for (va, s) in strings::strings_touching(&after, &change, min_length, &seen) {
                    if !seen.insert(s.string.clone()) {
                        continue;
                    }
                    if change.region == Region::Stack {
                        tight.push(TightString {
                            function:               *fva,
                            string:                 s.string,
                            encoding:               s.encoding,
                            program_counter:        tl.start,
                            stack_pointer:          sp,
                            original_stack_pointer: init_sp,
                            offset:                 va.wrapping_sub(sp),
                            frame_offset:           init_sp.wrapping_sub(va).wrapping_sub(emu.pointer_size()),
                        });
                    } else {
                        decoded.push(DecodedString {
                            address:          va,
                            address_type:     AddressType::from(change.region),
                            string:           s.string,
                            encoding:         s.encoding,
                            decoded_at:       tl.start,
                            decoding_routine: *fva,
                        });
                    }
                }
            }
        }
    }
    (tight, decoded)
}
