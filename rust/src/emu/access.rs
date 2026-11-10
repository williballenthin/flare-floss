//! Which instructions wrote and read which memory, and which calls took pointers
//! to it, along the path being emulated.
//!
//! `explore` forks the emulator state at each branch, so the records form a tree:
//! each record points at the record before it on the same path. A snapshot or a
//! memory view keeps only a `Mark`, the index of the newest record on its path,
//! so taking and restoring one costs nothing, and the paths stay apart.
//!
//! Consecutive accesses by one instruction to adjacent memory, like a decoding loop
//! or `rep stosb`, extend one record, so the log grows with the runs of accesses
//! rather than with each access.
use std::{cell::RefCell, rc::Rc};

use crate::program::VA;

const NONE: u32 = u32::MAX;

/// at most this many records are kept; later accesses aren't logged.
const MAX_RECORDS: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// the instruction wrote `[start, start+len)`.
    Write,
    /// the instruction read `[start, start+len)`.
    Read,
    /// the instruction wrote the argument registers in the mask `start`.
    Regs,
    /// the instruction is a call.
    Call,
    /// the call passes the pointer `start` as an argument.
    Arg,
}

#[derive(Debug, Clone, Copy)]
struct Record {
    pc:     VA,
    start:  VA,
    len:    u32,
    kind:   Kind,
    parent: u32,
}

impl Record {
    fn overlaps(&self, start: VA, end: VA) -> bool {
        self.start < end && start < self.start + self.len as u64
    }
}

/// The newest record on some path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark(u32);

impl Mark {
    pub const START: Mark = Mark(NONE);
}

/// An instruction that wrote part of some memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Writer {
    pub pc:    VA,
    /// whether some of the bytes it wrote are still there, rather than overwritten later.
    pub final_: bool,
}

/// The instructions that used some memory once its contents were complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Uses {
    /// the instructions that read it.
    pub readers:   Vec<VA>,
    /// the calls that took a pointer into it as an argument.
    pub passed_to: Vec<VA>,
}

#[derive(Debug, Default)]
pub struct AccessLog {
    records:  Vec<Record>,
    tail:     u32,
    /// the instruction that is executing.
    pub pc:   VA,
    /// the tail is shared with a mark, so it must not be extended.
    sealed:   bool,
    pub dropped: u64,
    pub writes:  u64,
}

pub type SharedAccessLog = Rc<RefCell<AccessLog>>;

impl AccessLog {
    pub fn new() -> AccessLog {
        AccessLog {
            tail: NONE,
            ..Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn write(&mut self, addr: VA, len: usize) {
        self.writes += 1;
        self.access(Kind::Write, addr, len as u32);
    }

    pub fn read(&mut self, addr: VA, len: usize) {
        self.access(Kind::Read, addr, len as u32);
    }

    /// the instruction that is executing wrote these argument registers.
    pub fn regs(&mut self, mask: u8) {
        self.push(Kind::Regs, mask as u64, 0);
    }

    /// the instruction at `pc` is a call that passes these pointers as arguments.
    pub fn call(&mut self, pc: VA, args: &[VA]) {
        self.pc = pc;
        self.push(Kind::Call, 0, 0);
        for &arg in args {
            self.push(Kind::Arg, arg, 1);
        }
    }

    fn access(&mut self, kind: Kind, addr: VA, len: u32) {
        if !self.sealed && self.tail != NONE && self.tail as usize == self.records.len() - 1 {
            let r = &mut self.records[self.tail as usize];
            if r.kind == kind && r.pc == self.pc && r.start + r.len as u64 == addr {
                r.len += len;
                return;
            }
            if r.kind == kind && r.pc == self.pc && addr + len as u64 == r.start {
                r.start = addr;
                r.len += len;
                return;
            }
        }
        self.push(kind, addr, len);
    }

    fn push(&mut self, kind: Kind, start: VA, len: u32) {
        if self.records.len() >= MAX_RECORDS {
            self.dropped += 1;
            return;
        }
        self.records.push(Record {
            pc: self.pc,
            start,
            len,
            kind,
            parent: self.tail,
        });
        self.tail = (self.records.len() - 1) as u32;
        self.sealed = false;
    }

    pub fn mark(&mut self) -> Mark {
        self.sealed = true;
        Mark(self.tail)
    }

    pub fn restore(&mut self, mark: Mark) {
        self.tail = mark.0;
        self.sealed = true;
    }

    /// forget all records; earlier marks are no longer valid.
    pub fn clear(&mut self) {
        self.records.clear();
        self.tail = NONE;
        self.sealed = false;
    }

    /// What was set since the previous call on the current path:
    /// the argument registers, as a mask, and the ranges of memory.
    pub fn since_call(&self) -> (u8, Vec<(VA, VA)>) {
        let (mut regs, mut written) = (0u8, vec![]);
        let mut i = self.tail;
        while i != NONE {
            let r = &self.records[i as usize];
            match r.kind {
                Kind::Call => break,
                Kind::Regs => regs |= r.start as u8,
                Kind::Write => written.push((r.start, r.start + r.len as u64)),
                Kind::Read | Kind::Arg => {}
            }
            i = r.parent;
        }
        (regs, written)
    }

    /// The instructions that used `[start, start+len)` as it was at `mark`.
    ///
    /// The contents are complete at the last write to the range before `mark`.
    /// Every path that continues from that write counts, up to its next write to the range,
    /// so this finds uses on either side of `mark`, and on the paths that fork later.
    pub fn uses(&self, mark: Mark, start: VA, len: usize) -> Uses {
        let end = start + len as u64;
        let mut complete = mark.0;
        while complete != NONE {
            let r = &self.records[complete as usize];
            if r.kind == Kind::Write && r.overlaps(start, end) {
                break;
            }
            complete = r.parent;
        }

        // a record's parent is always older, so one pass in order sees parents first.
        let first = complete.wrapping_add(1) as usize;
        let mut intact = vec![false; self.records.len() - first];
        let mut uses = Uses::default();
        for (i, r) in self.records[first..].iter().enumerate() {
            let reachable =
                r.parent == complete || (r.parent != NONE && r.parent as usize >= first && intact[r.parent as usize - first]);
            if !reachable {
                continue;
            }
            match r.kind {
                Kind::Write if r.overlaps(start, end) => continue,
                Kind::Read if r.overlaps(start, end) => uses.readers.push(r.pc),
                Kind::Arg if r.overlaps(start, end) => uses.passed_to.push(r.pc),
                _ => {}
            }
            intact[i] = true;
        }
        for pcs in [&mut uses.readers, &mut uses.passed_to] {
            pcs.sort();
            pcs.dedup();
        }
        uses
    }

    /// The instructions that wrote `[start, start+len)` on the path up to `mark`,
    /// by address.
    pub fn writers(&self, mark: Mark, start: VA, len: usize) -> Vec<Writer> {
        let end = start + len as u64;
        // the bytes that no later write has covered yet, as sorted, disjoint ranges.
        let mut uncovered: Vec<(VA, VA)> = vec![(start, end)];
        let mut writers: Vec<Writer> = vec![];
        let mut i = mark.0;
        while i != NONE {
            let r = self.records[i as usize];
            i = r.parent;
            if r.kind != Kind::Write || !r.overlaps(start, end) {
                continue;
            }
            let (rs, re) = (r.start, r.start + r.len as u64);
            let mut final_ = false;
            let mut next = Vec::with_capacity(uncovered.len() + 1);
            for &(us, ue) in &uncovered {
                if ue <= rs || re <= us {
                    next.push((us, ue));
                    continue;
                }
                final_ = true;
                if us < rs {
                    next.push((us, rs));
                }
                if re < ue {
                    next.push((re, ue));
                }
            }
            uncovered = next;
            writers.push(Writer { pc: r.pc, final_ });
        }
        writers.sort();
        writers.dedup_by(|b, a| {
            if a.pc == b.pc {
                a.final_ |= b.final_;
                true
            } else {
                false
            }
        });
        writers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcs(ws: &[Writer]) -> Vec<(VA, bool)> {
        ws.iter().map(|w| (w.pc, w.final_)).collect()
    }

    #[test]
    fn test_paths_stay_apart() {
        let mut log = AccessLog::new();
        log.pc = 0x10;
        log.write(0x1000, 1);
        let fork = log.mark();

        log.pc = 0x20;
        log.write(0x1001, 1);
        let left = log.mark();

        log.restore(fork);
        log.pc = 0x30;
        log.write(0x1001, 1);
        let right = log.mark();

        assert_eq!(pcs(&log.writers(left, 0x1000, 2)), vec![(0x10, true), (0x20, true)]);
        assert_eq!(pcs(&log.writers(right, 0x1000, 2)), vec![(0x10, true), (0x30, true)]);
    }

    #[test]
    fn test_overwritten() {
        let mut log = AccessLog::new();
        // a loop that writes the encoded string, then one that decodes it in place.
        log.pc = 0x10;
        for i in 0..4 {
            log.write(0x1000 + i, 1);
        }
        log.pc = 0x20;
        for i in 0..4 {
            log.write(0x1000 + i, 1);
        }
        assert_eq!(log.len(), 2);
        let mark = log.mark();
        assert_eq!(pcs(&log.writers(mark, 0x1000, 4)), vec![(0x10, false), (0x20, true)]);
        assert_eq!(pcs(&log.writers(mark, 0x2000, 4)), vec![]);
    }

    #[test]
    fn test_marked_tail_is_not_extended() {
        let mut log = AccessLog::new();
        log.pc = 0x10;
        log.write(0x1000, 1);
        let before = log.mark();
        log.write(0x1001, 1);
        let after = log.mark();
        assert_eq!(pcs(&log.writers(before, 0x1001, 1)), vec![]);
        assert_eq!(pcs(&log.writers(after, 0x1001, 1)), vec![(0x10, true)]);
    }

    #[test]
    fn test_uses() {
        let mut log = AccessLog::new();
        // build a string, then pass it to a call on one branch, and read it on the other.
        log.pc = 0x10;
        log.write(0x1000, 4);
        log.pc = 0x18;
        log.read(0x1000, 1);
        let built = log.mark();
        let fork = log.mark();

        log.call(0x20, &[0x1002, 0x5000]);
        log.pc = 0x28;
        log.write(0x1000, 4);
        log.call(0x30, &[0x1000]);
        let rebuilt = log.mark();

        log.restore(fork);
        log.pc = 0x40;
        log.read(0x0ffe, 4);
        log.read(0x2000, 4);

        assert_eq!(log.uses(built, 0x1000, 4), Uses {
            readers:   vec![0x18, 0x40],
            passed_to: vec![0x20],
        });
        // the second string in the same buffer has its own uses.
        assert_eq!(log.uses(rebuilt, 0x1000, 4), Uses {
            readers:   vec![],
            passed_to: vec![0x30],
        });
    }

    #[test]
    fn test_since_call() {
        let mut log = AccessLog::new();
        log.pc = 0x10;
        log.regs(0b0001);
        log.write(0x1000, 8);
        log.call(0x18, &[0x1000]);
        log.pc = 0x20;
        log.regs(0b0100);
        log.write(0x2000, 8);
        assert_eq!(log.since_call(), (0b0100, vec![(0x2000, 0x2008)]));
    }
}
