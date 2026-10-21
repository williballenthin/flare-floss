//! Strategies for driving the emulator through code.
//!
//! These correspond to the vivisect emulator drivers that FLOSS uses:
//!
//!   - `explore`: emulate every path through a function once,
//!     forking at each conditional branch and not following calls
//!     (viv-utils' `FullCoverageEmulatorDriver`).
//!   - `explore_to`: explore until reaching an address
//!     (viv-utils' `SinglePathEmulatorDriver`).
//!   - `run_to`: follow the one concrete path, into calls, until reaching an
//!     address or a limit (viv-utils' `DebuggerEmulatorDriver`).
//!
//! Observers see each instruction before and after it executes.
use std::collections::{HashMap, HashSet, VecDeque};

use lancelot::VA;

use crate::emu::{Call, CallPolicy, Emulator, Event, ExecOptions, Fault, Flow, Insn};

/// Whether to keep going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Continue,
    Stop,
}

pub trait Observer {
    /// called before executing each instruction, with the program counter at the instruction.
    fn before(&mut self, _emu: &mut Emulator, _insn: &Insn) -> Control {
        Control::Continue
    }

    /// called after executing an instruction; `call` describes the call it made, if any.
    fn after(&mut self, _emu: &mut Emulator, _insn: &Insn, _call: Option<&Call>) {}
}

/// An observer that doesn't observe anything.
pub struct Nothing;
impl Observer for Nothing {}

/// an upper bound on the instructions `explore` emulates, in case of pathological code.
const MAX_EXPLORE_INSNS: u64 = 1_000_000;

/// Emulate every path through the function at the emulator's program counter,
/// each instruction at most once.
///
/// At each conditional branch, the emulator state is saved, and both successors are queued
/// to be explored from that state. Calls are stepped over (see `ExecOptions`), returns end a path,
/// and so do instructions that fault. So each path is a concrete, plausible
/// execution through the function, but loops run at most once.
///
/// Returns false if an observer stopped the exploration.
pub fn explore(emu: &mut Emulator, opts: &ExecOptions, observer: &mut impl Observer) -> bool {
    let opts = ExecOptions {
        calls: CallPolicy::StepOver,
        ..*opts
    };

    let start = emu.pc();
    let t0 = std::time::Instant::now();
    let mut queue = VecDeque::from([emu.snapshot()]);
    let mut seen: HashSet<VA> = Default::default();
    let mut budget = MAX_EXPLORE_INSNS;
    let mut paths = 0;

    while let Some(state) = queue.pop_front() {
        emu.restore(&state);
        if seen.contains(&emu.pc()) {
            continue;
        }
        paths += 1;

        loop {
            if budget == 0 {
                log::debug!("explore: {start:#x}: instruction budget exhausted");
                return true;
            }
            budget -= 1;

            let pc = emu.pc();
            // import stubs aren't part of the function, and may be called many times.
            if !emu.is_stub(pc) {
                seen.insert(pc);
            }

            let Some(insn) = emu.decode(pc) else {
                log::trace!("explore: path ends at {pc:#x}: invalid instruction");
                break;
            };
            log::trace!("explore: {pc:#x} {:?}", insn.flow);

            if observer.before(emu, &insn) == Control::Stop {
                return false;
            }

            let call = match emu.execute(&insn, &opts) {
                Ok(Event::Executed(call)) => call,
                Ok(Event::Stop) => {
                    log::trace!("explore: path ends at {pc:#x}: stop");
                    break;
                }
                Err(Fault::Unsupported(..)) => {
                    // like vivisect, skip instructions the emulator doesn't support.
                    log::debug!("explore: skipping unsupported instruction at {pc:#x}");
                    emu.set_pc(insn.next());
                    None
                }
                Err(fault) => {
                    log::trace!("explore: path ends at {pc:#x}: {fault:?}");
                    break;
                }
            };

            observer.after(emu, &insn, call.as_ref());

            match insn.flow {
                Flow::CondJump(target) => {
                    for next in [target, insn.next()] {
                        if !seen.contains(&next) {
                            emu.set_pc(next);
                            queue.push_back(emu.snapshot());
                        }
                    }
                    break;
                }
                Flow::Ret | Flow::Trap => break,
                _ => {}
            }

            let next = emu.pc();
            if seen.contains(&next) {
                break;
            }
        }
    }

    log::debug!(
        "explore: {start:#x}: {} instructions, {paths} paths, {:?}",
        MAX_EXPLORE_INSNS - budget,
        t0.elapsed()
    );
    true
}

/// Explore from the emulator's program counter until reaching `target`
/// (before executing it). Returns true when the target was reached;
/// the emulator is then at `target`, in the state of the first path that got there.
pub fn explore_to(emu: &mut Emulator, opts: &ExecOptions, target: VA) -> bool {
    struct UntilTarget {
        target: VA,
    }

    impl Observer for UntilTarget {
        fn before(&mut self, emu: &mut Emulator, _insn: &Insn) -> Control {
            if emu.pc() == self.target {
                Control::Stop
            } else {
                Control::Continue
            }
        }
    }

    !explore(emu, opts, &mut UntilTarget { target })
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// the most instructions to emulate.
    pub max_insns: u64,
    /// the most times to execute any one address, to bound loops.
    pub max_hits:  u32,
}

/// How `run_to` ended.
#[derive(Debug, Clone)]
pub enum RunEnd {
    /// reached the target address.
    Reached,
    /// hit the instruction or address-hit limit.
    Limit,
    /// an API model stopped emulation, like ExitProcess.
    Stopped,
    /// emulation couldn't continue.
    Fault(Fault),
}

/// Emulate from the program counter, following calls, until reaching `target`
/// (before executing it), or hitting a limit or fault.
pub fn run_to(
    emu: &mut Emulator,
    opts: &ExecOptions,
    target: VA,
    limits: &Limits,
    observer: &mut impl Observer,
) -> RunEnd {
    let opts = ExecOptions {
        calls: CallPolicy::StepInto,
        ..*opts
    };

    let mut hits: HashMap<VA, u32> = Default::default();
    for _ in 0..limits.max_insns {
        let pc = emu.pc();
        if pc == target {
            return RunEnd::Reached;
        }

        let count = hits.entry(pc).or_default();
        if *count >= limits.max_hits {
            return RunEnd::Limit;
        }
        *count += 1;

        let Some(insn) = emu.decode(pc) else {
            return RunEnd::Fault(Fault::InvalidInstruction(pc));
        };

        if observer.before(emu, &insn) == Control::Stop {
            return RunEnd::Stopped;
        }

        match emu.execute(&insn, &opts) {
            Ok(Event::Executed(call)) => observer.after(emu, &insn, call.as_ref()),
            Ok(Event::Stop) => return RunEnd::Stopped,
            Err(fault) => return RunEnd::Fault(fault),
        }
    }

    RunEnd::Limit
}
