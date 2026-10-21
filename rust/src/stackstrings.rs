//! Stack strings: strings that a function builds on its stack,
//! typically one character (or a few) at a time with `mov` instructions.
//!
//! Emulate every path through each function, without following calls,
//! and look for strings in the function's stack frame:
//!   - at each call (the string is often an argument to the call), and
//!   - at the end of each basic block that contains at least `MIN_NUMBER_OF_MOVS`
//!     moves to memory (the string might never be used in a call).
//!
//! This is FLOSS's `stackstrings.py`.
use std::collections::{BTreeSet, HashSet};

use lancelot::VA;

use crate::{
    driver::{self, Control, Observer},
    emu::{CallPolicy, Emulator, ExecOptions, Flow, Insn},
    results::StackString,
    strings,
    workspace::Workspace,
};

/// the largest stack frame to search for strings.
const MAX_STACK_SIZE: u64 = 0x10000;
/// blocks with at least this many moves to memory might build a stack string.
const MIN_NUMBER_OF_MOVS: u32 = 5;

/// The stack frame contents at some point during emulation.
pub struct StackContext {
    pub pc:      VA,
    pub sp:      VA,
    pub init_sp: VA,
    pub stack:   Vec<u8>,
}

impl StackContext {
    /// capture the stack between the stack pointer and the initial stack pointer.
    pub fn capture(emu: &mut Emulator, pc: VA, init_sp: VA) -> Option<StackContext> {
        let sp = emu.sp();
        let size = init_sp.checked_sub(sp)?;
        if size > MAX_STACK_SIZE {
            log::debug!("stack size too big: {size:#x}");
            return None;
        }
        Some(StackContext {
            pc,
            sp,
            init_sp,
            stack: emu.read_mem(sp, size as usize),
        })
    }

    /// the strings in the frame, as `StackString`s from function `fva`.
    pub fn strings(
        &self,
        fva: VA,
        min_length: usize,
        exclude: &HashSet<String>,
        pointer_size: u64,
    ) -> Vec<StackString> {
        strings::extract_strings(&self.stack, min_length, exclude)
            .into_iter()
            .map(|s| StackString {
                function:               fva,
                string:                 s.string,
                encoding:               s.encoding,
                program_counter:        self.pc,
                stack_pointer:          self.sp,
                original_stack_pointer: self.init_sp,
                offset:                 s.offset as u64,
                frame_offset:           (self.init_sp - self.sp)
                    .wrapping_sub(s.offset as u64)
                    .wrapping_sub(pointer_size),
            })
            .collect()
    }
}

struct StackstringMonitor<'a> {
    init_sp:   VA,
    /// the last instruction of each basic block in the program.
    bb_ends:   &'a BTreeSet<VA>,
    /// moves to memory in the current basic block.
    mov_count: u32,
    contexts:  Vec<StackContext>,
}

impl Observer for StackstringMonitor<'_> {
    fn before(&mut self, emu: &mut Emulator, insn: &Insn) -> Control {
        if insn.flow == Flow::Call {
            self.contexts.extend(StackContext::capture(emu, insn.va, self.init_sp));
        }
        Control::Continue
    }

    fn after(&mut self, emu: &mut Emulator, insn: &Insn, _call: Option<&crate::emu::Call>) {
        if self.mov_count < MIN_NUMBER_OF_MOVS && insn.is_mov_to_memory {
            self.mov_count += 1;
        }

        // like FLOSS, this checks whether the *next* instruction ends a block.
        if self.bb_ends.contains(&emu.pc()) {
            if self.mov_count >= MIN_NUMBER_OF_MOVS {
                self.contexts.extend(StackContext::capture(emu, insn.va, self.init_sp));
            }
            self.mov_count = 0;
        }
    }
}

pub fn extract_stackstrings(
    ws: &Workspace,
    emu: &mut Emulator,
    functions: &[VA],
    min_length: usize,
) -> Vec<StackString> {
    let bb_ends: BTreeSet<VA> = ws
        .functions()
        .flat_map(|f| f.blocks.values().map(|bb| bb.last_insn()))
        .collect();

    // like FLOSS, don't use the API models here.
    let opts = ExecOptions {
        calls:      CallPolicy::StepOver,
        api_models: false,
        rep_max:    256,
    };

    let mut results = vec![];
    for &fva in functions {
        let mut seen = ws.referenced_strings(fva);

        emu.reset(fva);
        let mut monitor = StackstringMonitor {
            init_sp:   emu.sp(),
            bb_ends:   &bb_ends,
            mov_count: 0,
            contexts:  vec![],
        };
        driver::explore(emu, &opts, &mut monitor);

        for ctx in monitor.contexts.iter() {
            for s in ctx.strings(fva, min_length, &seen, emu.pointer_size()) {
                if seen.insert(s.string.clone()) {
                    results.push(s);
                }
            }
        }
    }
    results
}
