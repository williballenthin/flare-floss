//! Snapshots of the emulator state, and the differences between them.
//!
//! icicle's memory snapshots are copy-on-write: taking one is cheap (it
//! shares every page with the running emulator) and a page is only
//! copied when it's next written. That also makes comparing two snapshots
//! cheap: pages that are still shared can't differ.
//!
//! icicle's own CPU snapshot copies its whole 128KB register file, so we
//! save just the slots used by the x86 registers instead.
use icicle_vm::cpu::{
    mem::{self, physical, MemoryMapping},
    Cpu,
};
use lancelot::VA;

use super::{Layout, FILL_BYTE, PAGE_SIZE};

/// bytes per register slot in icicle's register file.
const REGISTER_SLOT_SIZE: u8 = 16;

#[derive(Clone)]
pub struct Snapshot {
    /// the register file: `REGISTER_SLOT_SIZE` bytes for each SLEIGH register id.
    regs:      Box<[u8]>,
    mem:       mem::Snapshot,
    /// the emulator's heap allocator state.
    heap_next: VA,
}

impl Snapshot {
    pub(super) fn capture(cpu: &mut Cpu, heap_next: VA) -> Snapshot {
        let n = cpu.arch.sleigh.num_registers();
        let mut regs = Vec::with_capacity(n * REGISTER_SLOT_SIZE as usize);
        for id in 0..n {
            let var = pcode::VarNode::new(id as pcode::VarId, REGISTER_SLOT_SIZE);
            match cpu.regs.get(var) {
                Some(slot) => regs.extend_from_slice(slot),
                None => regs.extend_from_slice(&[0u8; REGISTER_SLOT_SIZE as usize]),
            }
        }

        Snapshot {
            regs: regs.into_boxed_slice(),
            mem: cpu.mem.snapshot(),
            heap_next,
        }
    }

    /// restore this state into the CPU, returning the heap allocator state.
    pub(super) fn restore_into(&self, cpu: &mut Cpu) -> VA {
        for (id, slot) in self.regs.chunks(REGISTER_SLOT_SIZE as usize).enumerate() {
            let var = pcode::VarNode::new(id as pcode::VarId, REGISTER_SLOT_SIZE);
            if let Some(dst) = cpu.regs.get_mut(var) {
                dst.copy_from_slice(slot);
            }
        }
        cpu.mem.restore(self.mem.clone());
        cpu.exception.clear();
        // resets icicle's notion of the current block.
        let pc = cpu.read_pc();
        cpu.write_pc(pc);
        self.heap_next
    }

    pub fn memory(&self, layout: &Layout) -> MemoryView {
        MemoryView::new(self.mem.clone(), layout.clone(), self.heap_next)
    }
}

/// Where in the address space some (mapped) memory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Region {
    Stack,
    /// the image: global variables, constants, code.
    Global,
    Heap,
}

/// A contiguous run of bytes that differ between two memory views.
#[derive(Debug, Clone)]
pub struct Change {
    pub va:     VA,
    pub bytes:  Vec<u8>,
    pub region: Region,
}

enum Page<'a> {
    Data(&'a [u8; physical::PAGE_SIZE]),
    /// a mapped page that was never written: every byte has the same value.
    Fill(u8),
}

/// Read-only access to memory as of some snapshot.
pub struct MemoryView {
    mem:       mem::Snapshot,
    layout:    Layout,
    heap_next: VA,
}

impl MemoryView {
    pub(super) fn new(mem: mem::Snapshot, layout: Layout, heap_next: VA) -> MemoryView {
        MemoryView { mem, layout, heap_next }
    }

    pub fn region(&self, va: VA) -> Region {
        if self.layout.is_stack(va) {
            Region::Stack
        } else if self.layout.heap.contains(&va) {
            Region::Heap
        } else {
            Region::Global
        }
    }

    fn page(&self, page_va: VA) -> Option<Page<'_>> {
        match self.mem.mapping.get(page_va)? {
            MemoryMapping::Physical(m) => Some(Page::Data(&self.mem.physical.get(m.index).data().data)),
            MemoryMapping::Unallocated(m) => Some(Page::Fill(m.value)),
            MemoryMapping::Io(_) => None,
        }
    }

    /// read memory; unmapped bytes read as `FILL_BYTE`.
    pub fn read(&self, va: VA, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        let mut addr = va;
        while buf.len() < len {
            let page_va = addr & !(PAGE_SIZE - 1);
            let offset = (addr - page_va) as usize;
            let n = (PAGE_SIZE as usize - offset).min(len - buf.len());
            match self.page(page_va) {
                Some(Page::Data(data)) => buf.extend_from_slice(&data[offset..offset + n]),
                Some(Page::Fill(b)) => buf.extend(std::iter::repeat(b).take(n)),
                None => buf.extend(std::iter::repeat(FILL_BYTE).take(n)),
            }
            addr += n as u64;
        }
        buf
    }

    /// the page-aligned addresses of all mapped pages (not the void).
    fn mapped_pages(&self) -> impl Iterator<Item = VA> + '_ {
        self.mem
            .mapping
            .iter()
            .filter(|(_, _, mapping)| !matches!(mapping, MemoryMapping::Io(_)))
            .flat_map(|(start, end, _)| {
                let first = start & !(PAGE_SIZE - 1);
                (first..=end).step_by(PAGE_SIZE as usize)
            })
    }

    /// Find the bytes that changed from `before` to `self`.
    ///
    /// like FLOSS:
    ///   - within memory that existed before, report runs of bytes that differ,
    ///   - for memory that's new (heap allocations), report each run of new pages in full,
    ///   - ignore runs that are all zeros.
    pub fn changes_since(&self, before: &MemoryView) -> Vec<Change> {
        let mut changes: Vec<Change> = vec![];

        // the change being built, which may span pages.
        let mut current: Option<Change> = None;
        let flush = |current: &mut Option<Change>, changes: &mut Vec<Change>| {
            if let Some(change) = current.take() {
                if change.bytes.iter().any(|&b| b != 0) {
                    changes.push(change);
                }
            }
        };

        for page_va in self.mapped_pages() {
            let region = self.region(page_va);
            let after = self.page(page_va);
            let before_page = before.page(page_va);

            if let (Some(Page::Data(a)), Some(Page::Data(b))) = (&after, &before_page) {
                if std::ptr::eq(*a, *b) {
                    // still shared copy-on-write: nothing changed.
                    flush(&mut current, &mut changes);
                    continue;
                }
            }

            let read = |page: &Option<Page>, i: usize| -> u8 {
                match page {
                    Some(Page::Data(d)) => d[i],
                    Some(Page::Fill(b)) => *b,
                    None => FILL_BYTE,
                }
            };

            for i in 0..PAGE_SIZE as usize {
                let va = page_va + i as u64;
                let new = read(&after, i);
                // new pages are reported in full.
                let differs = before_page.is_none() || read(&before_page, i) != new;
                if differs {
                    match &mut current {
                        Some(change) if change.va + change.bytes.len() as u64 == va && change.region == region => {
                            change.bytes.push(new)
                        }
                        _ => {
                            flush(&mut current, &mut changes);
                            current = Some(Change {
                                va,
                                bytes: vec![new],
                                region,
                            });
                        }
                    }
                } else {
                    flush(&mut current, &mut changes);
                }
            }
        }
        flush(&mut current, &mut changes);

        changes
    }
}
