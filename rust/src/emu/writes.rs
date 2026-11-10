//! Which instructions wrote which memory, along the path being emulated.
//!
//! `explore` forks the emulator state at each branch, so the writes form a tree:
//! each record points at the write before it on the same path. A snapshot or a
//! memory view keeps only a `Mark`, the index of the newest record on its path,
//! so taking and restoring one costs nothing, and the paths stay apart.
//!
//! Consecutive writes by one instruction to adjacent memory, like a decoding loop
//! or `rep stosb`, extend one record, so the log grows with the runs of writes
//! rather than with each write.
use std::{cell::RefCell, rc::Rc};

use crate::program::VA;

const NONE: u32 = u32::MAX;

/// at most this many records are kept; later writes aren't logged.
const MAX_RECORDS: usize = 1 << 22;

#[derive(Debug, Clone, Copy)]
struct Record {
    pc:     VA,
    start:  VA,
    len:    u32,
    parent: u32,
}

/// The newest write on some path.
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

#[derive(Debug, Default)]
pub struct WriteLog {
    records:  Vec<Record>,
    tail:     u32,
    /// the instruction that is executing.
    pub pc:   VA,
    /// the tail is shared with a mark, so it must not be extended.
    sealed:   bool,
    pub dropped: u64,
    pub writes:  u64,
}

pub type SharedWriteLog = Rc<RefCell<WriteLog>>;

impl WriteLog {
    pub fn new() -> WriteLog {
        WriteLog {
            tail: NONE,
            ..Default::default()
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn record(&mut self, addr: VA, len: usize) {
        let len = len as u32;
        self.writes += 1;
        if !self.sealed && self.tail != NONE && self.tail as usize == self.records.len() - 1 {
            let r = &mut self.records[self.tail as usize];
            if r.pc == self.pc && r.start + r.len as u64 == addr {
                r.len += len;
                return;
            }
            if r.pc == self.pc && addr + len as u64 == r.start {
                r.start = addr;
                r.len += len;
                return;
            }
        }
        if self.records.len() >= MAX_RECORDS {
            self.dropped += 1;
            return;
        }
        self.records.push(Record {
            pc: self.pc,
            start: addr,
            len,
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

    /// forget all writes; earlier marks are no longer valid.
    pub fn clear(&mut self) {
        self.records.clear();
        self.tail = NONE;
        self.sealed = false;
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
            let (rs, re) = (r.start, r.start + r.len as u64);
            if re <= start || end <= rs {
                continue;
            }
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
        let mut log = WriteLog::new();
        log.pc = 0x10;
        log.record(0x1000, 1);
        let fork = log.mark();

        log.pc = 0x20;
        log.record(0x1001, 1);
        let left = log.mark();

        log.restore(fork);
        log.pc = 0x30;
        log.record(0x1001, 1);
        let right = log.mark();

        assert_eq!(pcs(&log.writers(left, 0x1000, 2)), vec![(0x10, true), (0x20, true)]);
        assert_eq!(pcs(&log.writers(right, 0x1000, 2)), vec![(0x10, true), (0x30, true)]);
    }

    #[test]
    fn test_overwritten() {
        let mut log = WriteLog::new();
        // a loop that writes the encoded string, then one that decodes it in place.
        log.pc = 0x10;
        for i in 0..4 {
            log.record(0x1000 + i, 1);
        }
        log.pc = 0x20;
        for i in 0..4 {
            log.record(0x1000 + i, 1);
        }
        assert_eq!(log.len(), 2);
        let mark = log.mark();
        assert_eq!(pcs(&log.writers(mark, 0x1000, 4)), vec![(0x10, false), (0x20, true)]);
        assert_eq!(pcs(&log.writers(mark, 0x2000, 4)), vec![]);
    }

    #[test]
    fn test_marked_tail_is_not_extended() {
        let mut log = WriteLog::new();
        log.pc = 0x10;
        log.record(0x1000, 1);
        let before = log.mark();
        log.record(0x1001, 1);
        let after = log.mark();
        assert_eq!(pcs(&log.writers(before, 0x1001, 1)), vec![]);
        assert_eq!(pcs(&log.writers(after, 0x1001, 1)), vec![(0x10, true)]);
    }
}
