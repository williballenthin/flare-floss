//! The program under analysis, as seen by lancelot:
//! functions, their basic blocks and instructions, imports, and callers.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use lancelot::{
    analysis::{
        cfg::flow::Flow,
        dis::{self, zydis},
        pe::ImportedSymbol,
    },
    arch::Arch,
    aspace::AddressSpace,
    loader::pe::PE,
    module::Module,
    workspace::{config::DynamicConfiguration, FunctionFlags, PEWorkspace},
    VA,
};

use crate::emu::Stub;

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
    ws:        PEWorkspace,
    functions: BTreeMap<VA, Function>,
    /// instruction address -> the function that contains it (the first, if shared).
    owners:    HashMap<VA, VA>,
    /// function address -> addresses of call instructions that call it.
    callers:   BTreeMap<VA, BTreeSet<VA>>,
    decoder:   zydis::Decoder,
}

impl Workspace {
    pub fn from_pe(buf: &[u8], sigs: &[std::path::PathBuf]) -> Result<Workspace> {
        let pe = PE::from_bytes(buf)?;
        let config = DynamicConfiguration::default().with_sig_paths(sigs);
        let ws = PEWorkspace::from_pe(Box::new(config), pe)?;
        let decoder = dis::get_disassembler(&ws.pe.module)?;

        let mut functions: BTreeMap<VA, Function> = Default::default();
        for &fva in ws.analysis.functions.keys() {
            functions.insert(fva, build_function(&ws, fva));
        }

        let mut owners: HashMap<VA, VA> = Default::default();
        for f in functions.values() {
            for insn in f.insns() {
                owners.entry(insn).or_insert(f.va);
            }
        }

        let mut callers: BTreeMap<VA, BTreeSet<VA>> = Default::default();
        for (&src, flows) in ws.cfg.flows.flows_by_src.iter() {
            for flow in flows.iter() {
                if let Flow::Call(lancelot::analysis::dis::Target::Direct(dst)) = flow {
                    callers.entry(*dst).or_default().insert(src);
                }
            }
        }

        Ok(Workspace {
            ws,
            functions,
            owners,
            callers,
            decoder,
        })
    }

    pub fn arch(&self) -> Arch {
        self.ws.pe.module.arch
    }

    pub fn module(&self) -> &Module {
        &self.ws.pe.module
    }

    pub fn base_address(&self) -> VA {
        self.ws.pe.module.address_space.base_address
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
        self.ws
            .analysis
            .functions
            .get(&fva)
            .map(|f| f.flags.intersects(FunctionFlags::THUNK))
            .unwrap_or(false)
    }

    /// the function's name, if it's known: from FLIRT or the exports.
    pub fn name(&self, fva: VA) -> Option<&str> {
        self.ws
            .analysis
            .names
            .names_by_address
            .get(&fva)
            .map(|s| s.as_str())
            .filter(|name| !name.starts_with("sub_"))
    }

    /// is the function recognized library code (via FLIRT)?
    pub fn is_library(&self, fva: VA) -> bool {
        self.name(fva).is_some()
    }

    /// names of the library functions in the program, by address.
    pub fn library_function_names(&self) -> BTreeMap<VA, String> {
        self.functions
            .keys()
            .filter_map(|&fva| self.name(fva).map(|name| (fva, name.to_string())))
            .collect()
    }

    /// addresses of the call instructions that call the given function.
    pub fn callers(&self, fva: VA) -> impl Iterator<Item = VA> + '_ {
        self.callers.get(&fva).into_iter().flat_map(|s| s.iter().copied())
    }

    /// the imports, as (address of the import table entry, API).
    pub fn imports(&self) -> Vec<(VA, Stub)> {
        self.ws
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
            .collect()
    }

    pub fn decode(&self, va: VA) -> Option<dis::DecodedInstruction> {
        let buf = self.ws.pe.module.address_space.read_bytes(va, 16).ok()?;
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
fn build_function(ws: &PEWorkspace, fva: VA) -> Function {
    let cfg = &ws.cfg;
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
                    Flow::UnconditionalJump(lancelot::analysis::dis::Target::Direct(va)) => *va,
                    _ => continue,
                };
                if succ != fva && ws.analysis.functions.contains_key(&succ) {
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
