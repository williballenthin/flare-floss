//! The program under analysis, indexed for the analyses:
//! functions, their basic blocks and instructions, imports, and callers.
//!
//! A backend provides the `Program`; everything here is derived from it.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    dis,
    program::{Arch, Function, Import, Program, Segment, VA},
};

pub struct Workspace {
    arch: Arch,
    base_address: VA,
    /// ordered by address.
    segments: Vec<Segment>,
    functions: BTreeMap<VA, Function>,
    thunks: BTreeSet<VA>,
    library_functions: BTreeSet<VA>,
    function_names: BTreeMap<VA, String>,
    imports: Vec<Import>,
    /// instruction address -> the function that contains it (the first, if shared).
    owners:    HashMap<VA, VA>,
    /// function address -> addresses of call instructions that call it.
    callers: BTreeMap<VA, BTreeSet<VA>>,
    /// see `callee_cleanup`.
    callee_cleanup: BTreeMap<VA, u16>,
}

impl Workspace {
    pub fn new(program: Program) -> Workspace {
        let mut segments = program.segments;
        segments.sort_by_key(|s| s.va);

        let mut ws = Workspace {
            arch: program.arch,
            base_address: program.base_address,
            segments,
            functions: program.functions.into_iter().map(|f| (f.va, f)).collect(),
            thunks: program.thunks,
            library_functions: program.library_functions,
            function_names: program.function_names,
            imports: program.imports,
            owners: Default::default(),
            callers: Default::default(),
            callee_cleanup: Default::default(),
        };

        let mut owners: HashMap<VA, VA> = Default::default();
        let mut callers: BTreeMap<VA, BTreeSet<VA>> = Default::default();
        let mut callee_cleanup: BTreeMap<VA, u16> = Default::default();
        for f in ws.functions.values() {
            for bb in f.blocks.values() {
                for &va in bb.insns.iter() {
                    owners.entry(va).or_insert(f.va);
                    let Some(insn) = ws.decode(va) else {
                        continue;
                    };
                    if insn.mnemonic == dis::Mnemonic::CALL {
                        if let Some(target) = dis::branch_target(&insn, va) {
                            callers.entry(target).or_default().insert(va);
                        }
                    }
                    if va == bb.last_insn() && ws.arch == Arch::X32 {
                        if let Some(cleanup) = dis::ret_cleanup(&insn).filter(|&n| n > 0) {
                            callee_cleanup.insert(f.va, cleanup);
                        }
                    }
                }
            }
        }

        // a call to a thunk, like `jmp sub_401017`, is a call to the thunk's target, too.
        // (compilers sometimes start a function with a jump into its loop,
        // which looks like a thunk to a separate function.)
        for &thunk in ws.thunks.iter() {
            let Some(insn) = ws.decode(thunk) else {
                continue;
            };
            if insn.mnemonic != dis::Mnemonic::JMP {
                continue;
            }
            if let Some(target) = dis::branch_target(&insn, thunk) {
                let thunk_callers = callers.get(&thunk).cloned().unwrap_or_default();
                callers.entry(target).or_default().extend(thunk_callers);
            }
        }

        ws.owners = owners;
        ws.callers = callers;
        ws.callee_cleanup = callee_cleanup;
        ws
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn base_address(&self) -> VA {
        self.base_address
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn functions(&self) -> impl Iterator<Item = &Function> + '_ {
        self.functions.values()
    }

    pub fn function(&self, va: VA) -> Option<&Function> {
        self.functions.get(&va)
    }

    /// the function that contains the given instruction.
    pub fn function_containing(&self, va: VA) -> Option<VA> {
        self.owners.get(&va).copied()
    }

    pub fn is_thunk(&self, fva: VA) -> bool {
        self.thunks.contains(&fva)
    }

    /// the function's name, if it has one.
    pub fn name(&self, fva: VA) -> Option<&str> {
        self.function_names.get(&fva).map(|s| s.as_str())
    }

    /// is the function library code, rather than the program's own?
    pub fn is_library(&self, fva: VA) -> bool {
        self.library_functions.contains(&fva)
    }

    /// names of the functions in the program that have one, by address.
    pub fn function_names(&self) -> &BTreeMap<VA, String> {
        &self.function_names
    }

    /// addresses of the call instructions that call the given function.
    pub fn callers(&self, fva: VA) -> impl Iterator<Item = VA> + '_ {
        self.callers.get(&fva).into_iter().flat_map(|s| s.iter().copied())
    }

    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// for x86: bytes of arguments each function pops when it returns,
    /// from its `ret N` instructions. functions that don't appear here pop nothing.
    pub fn callee_cleanup(&self) -> &BTreeMap<VA, u16> {
        &self.callee_cleanup
    }

    /// up to `len` bytes of the program's memory at the address: fewer at the end of a segment,
    /// and none outside of the segments.
    pub fn read_bytes(&self, va: VA, len: usize) -> &[u8] {
        let i = self.segments.partition_point(|s| s.va <= va);
        let Some(segment) = i.checked_sub(1).map(|i| &self.segments[i]) else {
            return &[];
        };
        if va >= segment.end() {
            return &[];
        }
        let start = (va - segment.va) as usize;
        &segment.bytes[start..segment.bytes.len().min(start + len)]
    }

    pub fn read_ptr(&self, va: VA) -> Option<VA> {
        let buf = self.read_bytes(va, self.arch.pointer_size());
        match self.arch {
            Arch::X32 => Some(u32::from_le_bytes(buf.try_into().ok()?) as u64),
            Arch::X64 => Some(u64::from_le_bytes(buf.try_into().ok()?)),
        }
    }

    pub fn decode(&self, va: VA) -> Option<dis::Instruction> {
        dis::decode(self.arch, self.read_bytes(va, dis::MAX_INSN_SIZE))
    }

    /// Strings referenced by the function's instructions, directly or via pointers.
    /// FLOSS excludes these from the stack and decoded strings found in the function,
    /// since they're plain old static strings.
    /// This is FLOSS's `get_referenced_strings`.
    pub fn referenced_strings(&self, fva: VA) -> HashSet<String> {
        let mut strings: HashSet<String> = Default::default();
        let Some(f) = self.function(fva) else {
            return strings;
        };

        for va in f.insns() {
            let Some(insn) = self.decode(va) else {
                continue;
            };
            for op in insn.visible_operands() {
                let candidate = match &op.kind {
                    dis::DecodedOperandKind::Imm(imm) if !imm.is_relative => imm.value,
                    dis::DecodedOperandKind::Mem(mem) if mem.base == dis::Register::RIP => {
                        match insn.calc_absolute_address(va, op) {
                            Ok(va) => va,
                            Err(_) => continue,
                        }
                    }
                    // like `[0x401000]` or `[0x401000 + eax*4]`, but not `[eax + 0x10]`.
                    dis::DecodedOperandKind::Mem(mem)
                        if mem.base == dis::Register::NONE || mem.index != dis::Register::NONE =>
                    {
                        mem.disp.displacement as u64
                    }
                    _ => continue,
                };

                // follow pointers to pointers to strings, a few levels deep.
                let mut p = candidate;
                for _ in 0..10 {
                    if self.read_bytes(p, 1).is_empty() {
                        break;
                    }
                    if let Some(s) = self.read_string(p) {
                        strings.extend(s.split("\r\n").map(|s| s.trim_end_matches('\0').to_string()));
                    }
                    let Some(next) = self.read_ptr(p) else {
                        break;
                    };
                    if next == p {
                        break;
                    }
                    p = next;
                }
            }
        }
        strings
    }

    /// the ASCII or UTF-16LE string at the address, like vivisect's `detectString`/`detectUnicode`.
    fn read_string(&self, va: VA) -> Option<String> {
        let buf = self.read_bytes(va, 0x1000);

        let printable = |b: u8| (0x20..0x7f).contains(&b) || (0x09..=0x0d).contains(&b);

        let ascii: Vec<u8> = buf.iter().copied().take_while(|&b| printable(b)).collect();
        if ascii.len() >= 4 && buf.get(ascii.len()) == Some(&0) {
            return Some(String::from_utf8_lossy(&ascii).to_string());
        }

        let wide: Vec<u8> = buf
            .chunks(2)
            .take_while(|c| c.len() == 2 && printable(c[0]) && c[1] == 0)
            .map(|c| c[0])
            .collect();
        if wide.len() > 4 && buf.get(wide.len() * 2) == Some(&0) {
            return Some(String::from_utf8_lossy(&wide).to_string());
        }

        None
    }
}
