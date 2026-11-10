//! Program analysis via lancelot, which is pure Rust: PE files and shellcode.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use lancelot::{
    analysis::{
        cfg::{flow::Flow, InstructionIndex, CFG},
        dis::Target,
        pe::ImportedSymbol,
    },
    aspace::{AddressSpace, RelativeAddressSpace},
    loader::pe::PE,
    module::{Module, Permissions},
    workspace::{FunctionFlags, PEWorkspace},
};

use crate::program::{Arch, BasicBlock, Function, Import, Program, Segment, VA};

pub mod flirt;

use flirt::{SignatureFile, Signatures};

/// Load a PE file. FLIRT signatures are optional (see `flirt::builtin`).
pub fn load_pe(buf: &[u8], sigs: &[SignatureFile]) -> Result<Program> {
    let pe = PE::from_bytes(buf)?;
    let ws = PEWorkspace::from_pe(Box::new(Signatures(sigs.to_vec())), pe)?;

    let thunks = ws
        .analysis
        .functions
        .iter()
        .filter(|(_, f)| f.flags.intersects(FunctionFlags::THUNK))
        .map(|(&va, _)| va)
        .collect();

    // lancelot names functions from exports and FLIRT signatures.
    let function_names: BTreeMap<VA, String> = ws
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
            Import {
                va: import.address,
                dll,
                name,
            }
        })
        .collect();

    let starts: BTreeSet<VA> = ws.analysis.functions.keys().copied().collect();
    Ok(Program {
        library_functions: function_names.keys().copied().collect(),
        function_names,
        imports,
        ..get_program(&ws.pe.module, &ws.cfg, &starts, thunks)
    })
}

/// Load raw shellcode, which starts executing at its first byte.
pub fn load_shellcode(buf: &[u8], arch: Arch) -> Result<Program> {
    // like vivisect's shellcode workspaces.
    const BASE_ADDRESS: VA = 0x690000;

    let size = ((buf.len() as u64 + 0xFFF) & !0xFFF).max(0x1000);
    let mut padded = buf.to_vec();
    padded.resize(size as usize, 0);
    let module = Module {
        arch:          match arch {
            Arch::X32 => lancelot::arch::Arch::X32,
            Arch::X64 => lancelot::arch::Arch::X64,
        },
        sections:      vec![lancelot::module::Section {
            physical_range: 0..buf.len() as u64,
            virtual_range:  BASE_ADDRESS..BASE_ADDRESS + size,
            permissions:    Permissions::RWX,
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

    Ok(get_program(&module, &cfg, &starts, thunks))
}

fn get_program(module: &Module, cfg: &CFG, starts: &BTreeSet<VA>, thunks: BTreeSet<VA>) -> Program {
    let segments = module
        .sections
        .iter()
        .map(|section| {
            let range = &section.virtual_range;
            let size = (range.end - range.start) as usize;
            let mut bytes = module.address_space.read_bytes(range.start, size).unwrap_or_default();
            bytes.resize(size, 0);
            Segment {
                va: range.start,
                name: section.name.clone(),
                executable: section.permissions.intersects(Permissions::X),
                bytes,
            }
        })
        .collect();

    Program {
        arch: match module.arch {
            lancelot::arch::Arch::X32 => Arch::X32,
            lancelot::arch::Arch::X64 => Arch::X64,
        },
        base_address: module.address_space.base_address,
        segments,
        functions: starts.iter().map(|&fva| get_function(cfg, starts, fva)).collect(),
        thunks,
        library_functions: Default::default(),
        function_names: Default::default(),
        imports: vec![],
    }
}

/// Collect the blocks reachable from the function entry via jumps and fallthroughs,
/// not crossing into other functions (tail calls).
fn get_function(cfg: &CFG, starts: &BTreeSet<VA>, fva: VA) -> Function {
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
