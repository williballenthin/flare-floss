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
//!
//! At the same checkpoints, also look for strings that the function wrote to global memory
//! (which FLOSS doesn't). These are reported as decoded strings, since they have addresses.
use std::collections::{BTreeSet, HashSet};

use lancelot::VA;

use crate::{
    driver::{self, Control, Observer},
    emu::{snapshot::Region, CallPolicy, Emulator, ExecOptions, Flow, Insn, MemoryView},
    results::{AddressType, DecodedString, StackString},
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

/// Strings written to global memory, found at some checkpoint.
pub struct GlobalStrings {
    pub pc:      VA,
    pub strings: Vec<(VA, strings::FoundString)>,
}

struct StackstringMonitor<'a> {
    init_sp:   VA,
    /// memory when the function started.
    start:     MemoryView,
    min_length: usize,
    globals:   Vec<GlobalStrings>,
    /// the last instruction of each basic block in the program.
    bb_ends:   &'a BTreeSet<VA>,
    /// moves to memory in the current basic block.
    mov_count: u32,
    contexts:  Vec<StackContext>,
}

impl StackstringMonitor<'_> {
    fn checkpoint(&mut self, emu: &mut Emulator, pc: VA) {
        self.contexts.extend(StackContext::capture(emu, pc, self.init_sp));

        let memory = emu.memory();
        let changes: Vec<_> = memory
            .changes_since(&self.start, None)
            .into_iter()
            .filter(|change| change.region == Region::Global)
            .collect();
        let found: Vec<_> = strings::strings_touching(&self.start, &memory, &changes, self.min_length, &Default::default())
            .into_iter()
            .map(|w| (w.va, w.string))
            .collect();
        if !found.is_empty() {
            self.globals.push(GlobalStrings { pc, strings: found });
        }
    }
}

impl Observer for StackstringMonitor<'_> {
    fn before(&mut self, emu: &mut Emulator, insn: &Insn) -> Control {
        if insn.flow == Flow::Call {
            self.checkpoint(emu, insn.va);
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
                self.checkpoint(emu, insn.va);
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
) -> (Vec<StackString>, Vec<DecodedString>) {
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
    let mut globals = vec![];
    for &fva in functions {
        let mut seen = ws.referenced_strings(fva);

        emu.reset(fva);
        let mut monitor = StackstringMonitor {
            start:     emu.memory(),
            min_length,
            globals:   vec![],
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

        for g in monitor.globals.iter() {
            for (va, s) in g.strings.iter() {
                if seen.insert(s.string.clone()) {
                    globals.push(DecodedString {
                        address:          *va,
                        address_type:     AddressType::Global,
                        string:           s.string.clone(),
                        encoding:         s.encoding,
                        decoded_at:       g.pc,
                        decoding_routine: fva,
                    });
                }
            }
        }
    }
    (results, globals)
}
