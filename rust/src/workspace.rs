//! The program under analysis, as seen by lancelot:
//! functions, their basic blocks and instructions, imports, and callers.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use lancelot::{
    analysis::{
        cfg::{flow::Flow, InstructionIndex, CFG},
        dis::{self, zydis, Target},
        pe::ImportedSymbol,
    },
    arch::Arch,
    aspace::{AddressSpace, RelativeAddressSpace},
    loader::pe::PE,
    module::Module,
    workspace::{FunctionFlags, PEWorkspace},
    VA,
};

use crate::{
    emu::Stub,
    flirt::{SignatureFile, Signatures},
};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub va:           VA,
    /// addresses of the instructions in the block.
    pub insns:        Vec<VA>,
    /// the blocks that this block flows to (excluding calls and tail calls).
    pub successors:   Vec<VA>,
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

pub struct Workspace {
    module:    Module,
    cfg:       CFG,
    functions: BTreeMap<VA, Function>,
    /// functions that just jump elsewhere, like `jmp [__imp_malloc]`.
    thunks:    BTreeSet<VA>,
    /// names of library functions, from FLIRT signatures (when enabled).
    names:     BTreeMap<VA, String>,
    /// import address table entries.
    imports:   Vec<(VA, Stub)>,
    /// instruction address -> the function that contains it (the first, if shared).
    owners:    HashMap<VA, VA>,
    /// function address -> addresses of call instructions that call it.
    callers:   BTreeMap<VA, BTreeSet<VA>>,
    decoder:   zydis::Decoder,
}

impl Workspace {
    /// Load a PE file. FLIRT signatures are optional.
    pub fn from_pe(buf: &[u8], sigs: &[SignatureFile]) -> Result<Workspace> {
        let pe = PE::from_bytes(buf)?;
        let ws = PEWorkspace::from_pe(Box::new(Signatures(sigs.to_vec())), pe)?;

        let thunks = ws
            .analysis
            .functions
            .iter()
            .filter(|(_, f)| f.flags.intersects(FunctionFlags::THUNK))
            .map(|(&va, _)| va)
            .collect();

        let names = ws
            .analysis
            .names
            .names_by_address
            .iter()
            .filter(|(va, name)| ws.analysis.functions.contains_key(va) && !name.starts_with("sub_"))
            .map(|(&va, name)| (va, name.clone()))
            .collect();

        let imports = ws
            .analysis
            .imports
            .values()
            .map(|import| {
                let dll = import.dll.to_lowercase();
                let dll = dll.strip_suffix(".dll").unwrap_or(&dll).to_string();
                let name = match &import.symbol {
                    ImportedSymbol::Name(name) => name.clone(),
                    ImportedSymbol::Ordinal(ord) => format!("#{ord}"),
                };
                (import.address, Stub { dll, name })
            })
            .collect();

        let starts = ws.analysis.functions.keys().copied().collect();
        Workspace::new(ws.pe.module, ws.cfg, starts, thunks, names, imports)
    }

    /// Load raw shellcode, which starts executing at its first byte.
    pub fn from_shellcode(buf: &[u8], arch: Arch) -> Result<Workspace> {
        // like vivisect's shellcode workspaces.
        const BASE_ADDRESS: VA = 0x690000;

        let size = ((buf.len() as u64 + 0xFFF) & !0xFFF).max(0x1000);
        let mut padded = buf.to_vec();
        padded.resize(size as usize, 0);
        let module = Module {
            arch,
            sections: vec![lancelot::module::Section {
                physical_range: 0..buf.len() as u64,
                virtual_range:  BASE_ADDRESS..BASE_ADDRESS + size,
                permissions:    lancelot::module::Permissions::RWX,
                name:           "shellcode".to_string(),
            }],
            address_space: RelativeAddressSpace::from_buf(&padded).into_absolute(BASE_ADDRESS)?,
        };

        let mut insns: InstructionIndex = Default::default();
        let mut starts: BTreeSet<VA> = BTreeSet::from([BASE_ADDRESS]);
        insns.build_index(&module, BASE_ADDRESS)?;
        loop {
            let new_code = lancelot::analysis::cfg::code_references::find_new_code_references(&module, &insns)?;
            if new_code.is_empty() {
                break;
            }
            for va in new_code {
                insns.build_index(&module, va)?;
                starts.insert(va);
            }
        }
        let cfg = CFG::from_instructions(&module, insns)?;

        // call targets are functions, too.
        for flows in cfg.flows.flows_by_src.values() {
            for flow in flows.iter() {
                if let Flow::Call(Target::Direct(dst)) = flow {
                    if cfg.insns.insns_by_address.contains_key(dst) {
                        starts.insert(*dst);
                    }
                }
            }
        }
        let thunks = lancelot::analysis::cfg::thunk::find_thunks(&cfg, starts.iter());

        Workspace::new(module, cfg, starts, thunks, Default::default(), vec![])
    }

    fn new(
        module: Module,
        cfg: CFG,
        starts: BTreeSet<VA>,
        thunks: BTreeSet<VA>,
        names: BTreeMap<VA, String>,
        imports: Vec<(VA, Stub)>,
    ) -> Result<Workspace> {
        let decoder = dis::get_disassembler(&module)?;

        let mut functions: BTreeMap<VA, Function> = Default::default();
        for &fva in starts.iter() {
            functions.insert(fva, build_function(&cfg, &starts, fva));
        }

        let mut owners: HashMap<VA, VA> = Default::default();
        for f in functions.values() {
            for insn in f.insns() {
                owners.entry(insn).or_insert(f.va);
            }
        }

        let mut callers: BTreeMap<VA, BTreeSet<VA>> = Default::default();
        for (&src, flows) in cfg.flows.flows_by_src.iter() {
            for flow in flows.iter() {
                if let Flow::Call(Target::Direct(dst)) = flow {
                    callers.entry(*dst).or_default().insert(src);
                }
            }
        }

        // a call to a thunk, like `jmp sub_401017`, is a call to the thunk's target, too.
        // (compilers sometimes start a function with a jump into its loop,
        // which looks like a thunk to a separate function.)
        for &thunk in thunks.iter() {
            let Some(flows) = cfg.flows.flows_by_src.get(&thunk) else {
                continue;
            };
            for flow in flows.iter() {
                if let Flow::UnconditionalJump(Target::Direct(dst)) = flow {
                    let thunk_callers = callers.get(&thunk).cloned().unwrap_or_default();
                    callers.entry(*dst).or_default().extend(thunk_callers);
                }
            }
        }

        Ok(Workspace {
            module,
            cfg,
            functions,
            thunks,
            names,
            imports,
            owners,
            callers,
            decoder,
        })
    }

    pub fn arch(&self) -> Arch {
        self.module.arch
    }

    pub fn module(&self) -> &Module {
        &self.module
    }

    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    pub fn base_address(&self) -> VA {
        self.module.address_space.base_address
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

    /// the function's name, if it's a recognized library function.
    pub fn name(&self, fva: VA) -> Option<&str> {
        self.names.get(&fva).map(|s| s.as_str())
    }

    /// is the function recognized library code (via FLIRT)?
    pub fn is_library(&self, fva: VA) -> bool {
        self.names.contains_key(&fva)
    }

    /// names of the library functions in the program, by address.
    pub fn library_function_names(&self) -> BTreeMap<VA, String> {
        self.names.clone()
    }

    /// addresses of the call instructions that call the given function.
    pub fn callers(&self, fva: VA) -> impl Iterator<Item = VA> + '_ {
        self.callers.get(&fva).into_iter().flat_map(|s| s.iter().copied())
    }

    /// the imports, as (address of the import table entry, API).
    pub fn imports(&self) -> Vec<(VA, Stub)> {
        self.imports.clone()
    }

    pub fn decode(&self, va: VA) -> Option<dis::DecodedInstruction> {
        let buf = self.module.address_space.read_bytes(va, 16).ok()?;
        dis::decode(&self.decoder, &buf).ok()?
    }

    /// for x86: bytes of arguments each function pops when it returns,
    /// from its `ret N` instructions. functions that don't appear here pop nothing.
    pub fn callee_cleanup(&self) -> BTreeMap<VA, u16> {
        if let Arch::X64 = self.arch() {
            return Default::default();
        }

        let mut cleanup = BTreeMap::new();
        for f in self.functions.values() {
            for bb in f.blocks.values() {
                let Some(insn) = self.decode(bb.last_insn()) else {
                    continue;
                };
                if insn.mnemonic != zydis::Mnemonic::RET {
                    continue;
                }
                if let Some(op) = insn.operands().first() {
                    if let dis::DecodedOperandKind::Imm(imm) = &op.kind {
                        if imm.value > 0 {
                            cleanup.insert(f.va, imm.value as u16);
                        }
                    }
                }
            }
        }
        cleanup
    }
}

impl Workspace {
    fn is_valid_pointer(&self, va: VA) -> bool {
        self.module().probe_va(va, lancelot::module::Permissions::R)
    }

    /// Strings referenced by the function's instructions, directly or via pointers.
    /// FLOSS excludes these from the stack and decoded strings found in the function,
    /// since they're plain old static strings.
    /// This is FLOSS's `get_referenced_strings`.
    pub fn referenced_strings(&self, fva: VA) -> std::collections::HashSet<String> {
        let mut strings: std::collections::HashSet<String> = Default::default();
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
                    dis::DecodedOperandKind::Mem(mem) if mem.base == zydis::Register::RIP => {
                        match insn.calc_absolute_address(va, op) {
                            Ok(va) => va,
                            Err(_) => continue,
                        }
                    }
                    // like `[0x401000]` or `[0x401000 + eax*4]`, but not `[eax + 0x10]`.
                    dis::DecodedOperandKind::Mem(mem)
                        if mem.base == zydis::Register::NONE || mem.index != zydis::Register::NONE =>
                    {
                        mem.disp.displacement as u64
                    }
                    _ => continue,
                };

                // follow pointers to pointers to strings, a few levels deep.
                let mut p = candidate;
                for _ in 0..10 {
                    if !self.is_valid_pointer(p) {
                        break;
                    }
                    if let Some(s) = self.read_string(p) {
                        strings.extend(s.split("\r\n").map(|s| s.trim_end_matches('\0').to_string()));
                    }
                    let Ok(next) = self.module().read_va_at_va(p) else {
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
        let buf = self.module().address_space.read_bytes(va, 0x1000).ok().or_else(|| {
            // near the end of a section.
            (1..0x1000)
                .rev()
                .step_by(0x100)
                .find_map(|n| self.module().address_space.read_bytes(va, n).ok())
        })?;

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

/// Collect the blocks reachable from the function entry via jumps and fallthroughs,
/// not crossing into other functions (tail calls).
fn build_function(cfg: &CFG, starts: &BTreeSet<VA>, fva: VA) -> Function {
    let mut blocks: BTreeMap<VA, BasicBlock> = Default::default();
    let mut queue = vec![fva];

    while let Some(va) = queue.pop() {
        if blocks.contains_key(&va) {
            continue;
        }
        let Some(bb) = cfg.basic_blocks.blocks_by_address.get(&va) else {
            continue;
        };

        let insns: Vec<VA> = cfg
            .insns
            .insns_by_address
            .range(bb.address..=bb.address_of_last_insn)
            .map(|(&va, _)| va)
            .collect();

        let mut successors = vec![];
        if let Some(flows) = cfg.flows.flows_by_src.get(&bb.address_of_last_insn) {
            for flow in flows.iter() {
                let succ = match flow {
                    Flow::Fallthrough(va) => *va,
                    Flow::ConditionalJump(va) => *va,
                    Flow::UnconditionalJump(Target::Direct(va)) => *va,
                    _ => continue,
                };
                if succ != fva && starts.contains(&succ) {
                    // tail call
                    continue;
                }
                if cfg.basic_blocks.blocks_by_address.contains_key(&succ) {
                    successors.push(succ);
                }
            }
        }

        queue.extend(successors.iter().copied());
        blocks.insert(va, BasicBlock {
            va,
            insns,
            successors,
        });
    }

    Function { va: fva, blocks }
}
