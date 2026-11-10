//! The program under analysis, as plain data: what a backend (see `crate::backend`)
//! provides, and all that the rest of floss-rs knows about the program.
use std::collections::{BTreeMap, BTreeSet};

pub type VA = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X32,
    X64,
}

impl Arch {
    pub fn pointer_size(&self) -> usize {
        match self {
            Arch::X32 => 4,
            Arch::X64 => 8,
        }
    }

    pub fn bitness(&self) -> u32 {
        match self {
            Arch::X32 => 32,
            Arch::X64 => 64,
        }
    }
}

/// A range of the program's memory, like a PE section.
#[derive(Debug, Clone)]
pub struct Segment {
    pub va:         VA,
    pub name:       String,
    pub executable: bool,
    /// the contents, as loaded: bytes that the file doesn't initialize are zero.
    pub bytes:      Vec<u8>,
}

impl Segment {
    pub fn end(&self) -> VA {
        self.va + self.bytes.len() as u64
    }
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub va:         VA,
    /// addresses of the instructions in the block.
    pub insns:      Vec<VA>,
    /// the blocks that this block flows to (excluding calls and tail calls).
    pub successors: Vec<VA>,
}

impl BasicBlock {
    pub fn last_insn(&self) -> VA {
        *self.insns.last().expect("non-empty block")
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub va:     VA,
    /// keyed by block address; the entry block is `va`.
    pub blocks: BTreeMap<VA, BasicBlock>,
}

impl Function {
    pub fn insns(&self) -> impl Iterator<Item = VA> + '_ {
        self.blocks.values().flat_map(|bb| bb.insns.iter().copied())
    }
}

/// An entry of the import address table: the API that the program expects to find there.
#[derive(Debug, Clone)]
pub struct Import {
    /// address of the import table entry.
    pub va:   VA,
    /// lowercase DLL name without extension, like "kernel32".
    pub dll:  String,
    /// the exported name, or "#<ordinal>".
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub arch:         Arch,
    pub base_address: VA,
    pub segments:     Vec<Segment>,
    pub functions:    Vec<Function>,
    /// functions that just jump elsewhere, like `jmp [__imp_malloc]`.
    pub thunks:       BTreeSet<VA>,
    /// functions that are library code, like the C runtime, rather than the program's own.
    pub library_functions: BTreeSet<VA>,
    /// names of functions, where they're known: from signatures, symbols, or exports.
    pub function_names: BTreeMap<VA, String>,
    pub imports:      Vec<Import>,
}
