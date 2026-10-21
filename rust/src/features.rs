//! Which functions might decode strings?
//!
//! A port of FLOSS's `identify.py` and `features/`: each function gets
//! features, like "has a tight loop" or "has a non-zeroing xor", each with
//! a weight and a score. The weighted average ranks the candidate
//! decoding routines. Functions with tight loops also get tight string
//! extraction instead of stack string extraction.
use std::collections::{BTreeMap, BTreeSet};

use lancelot::{
    analysis::dis::{zydis, DecodedOperandKind},
    arch::Arch,
    VA,
};

use crate::workspace::{BasicBlock, Function, Workspace};

const LOW: f64 = 0.25;
const MEDIUM: f64 = 0.50;
const HIGH: f64 = 0.75;
const SEVERE: f64 = 1.00;

/// functions with fewer blocks than this, that contain a tight loop,
/// are "tight functions": always emulated as decoding routines.
const TIGHT_FUNCTION_MAX_BLOCKS: usize = 10;

/// non-zeroing xors this close to the start of the function, or the end of a
/// returning block, are probably security cookie checks.
const SECURITY_COOKIE_BYTES_DELTA: u64 = 0x40;

/// A loop of one or two blocks that writes memory and doesn't call anything:
/// the shape of most inline string decoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TightLoop {
    /// the first block of the loop.
    pub start: VA,
    /// the block that follows the loop.
    pub end:   VA,
    /// the loop is a single block that branches to itself.
    pub very_tight: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Feature {
    BlockCount(usize),
    InstructionCount(usize),
    Arguments(usize),
    CallsTo { count: usize, max: usize },
    Loop(usize),
    TightLoop(TightLoop),
    TightFunction,
    Nzxor(VA),
    Shift(VA),
    Mov(VA),
    NzxorTightLoop,
    NzxorLoop,
}

impl Feature {
    fn weight(&self) -> f64 {
        match self {
            Feature::BlockCount(_) | Feature::InstructionCount(_) | Feature::Arguments(_) => LOW,
            Feature::CallsTo { .. } | Feature::Loop(_) | Feature::Mov(_) => MEDIUM,
            Feature::TightLoop(_) | Feature::Nzxor(_) | Feature::Shift(_) => HIGH,
            Feature::TightFunction | Feature::NzxorTightLoop | Feature::NzxorLoop => SEVERE,
        }
    }

    fn score(&self) -> f64 {
        match *self {
            Feature::BlockCount(n) if n > 30 => 0.1,
            Feature::BlockCount(n) if (3..=10).contains(&n) => 1.0,
            Feature::BlockCount(_) => 0.4,
            Feature::InstructionCount(n) if n > 10 => 0.8,
            Feature::InstructionCount(_) => 0.1,
            Feature::Arguments(n) if (1..=4).contains(&n) => 1.0,
            Feature::Arguments(n) if (5..=6).contains(&n) => 0.5,
            Feature::Arguments(_) => 0.0,
            Feature::CallsTo { count, max } => count as f64 / max.max(1) as f64,
            // tight functions are always emulated, so this doesn't need to boost the score.
            Feature::TightFunction => 0.0,
            _ => 1.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionFeatures {
    pub va:       VA,
    pub features: Vec<Feature>,
    pub score:    f64,
    pub xrefs_to: usize,
}

impl FunctionFeatures {
    pub fn tight_loops(&self) -> Vec<TightLoop> {
        self.features
            .iter()
            .filter_map(|f| match f {
                Feature::TightLoop(tl) => Some(*tl),
                _ => None,
            })
            .collect()
    }

    pub fn is_tight_function(&self) -> bool {
        self.features.contains(&Feature::TightFunction)
    }
}

/// Compute the features of every non-library, non-thunk function.
pub fn find_decoding_function_features(ws: &Workspace) -> BTreeMap<VA, FunctionFeatures> {
    let candidates: Vec<&Function> = ws
        .functions()
        .filter(|f| !ws.is_thunk(f.va) && !ws.is_library(f.va))
        .collect();

    let max_calls_to = candidates.iter().map(|f| ws.callers(f.va).count()).max().unwrap_or(0);

    candidates
        .into_iter()
        .map(|f| {
            let features = extract_features(ws, f, max_calls_to);
            let total_weight: f64 = features.iter().map(|f| f.weight()).sum();
            let score = features.iter().map(|f| f.weight() * f.score()).sum::<f64>() / total_weight;
            let score = (score * 1000.0).round() / 1000.0;
            (f.va, FunctionFeatures {
                va: f.va,
                features,
                score,
                xrefs_to: ws.callers(f.va).count(),
            })
        })
        .collect()
}

fn extract_features(ws: &Workspace, f: &Function, max_calls_to: usize) -> Vec<Feature> {
    let mut features = vec![
        Feature::BlockCount(f.blocks.len()),
        Feature::InstructionCount(f.insns().count()),
        Feature::Arguments(argument_count(ws, f)),
        Feature::CallsTo {
            count: ws.callers(f.va).count(),
            max:   max_calls_to,
        },
    ];

    features.extend(find_loops(f).into_iter().map(Feature::Loop));
    features.extend(find_tight_loops(ws, f).into_iter().map(Feature::TightLoop));

    for bb in f.blocks.values() {
        for &va in bb.insns.iter() {
            let Some(insn) = ws.decode(va) else {
                continue;
            };
            use zydis::Mnemonic as M;
            match insn.mnemonic {
                M::XOR if is_nonzeroing_xor(&insn) && !is_security_cookie(ws, f, bb, va, &insn) => {
                    features.push(Feature::Nzxor(va))
                }
                M::SHL | M::SHR | M::ROL | M::ROR => features.push(Feature::Shift(va)),
                M::MOV if is_mov_via_register(&insn) => features.push(Feature::Mov(va)),
                _ => {}
            }
        }
    }

    // abstract features, derived from the ones above.
    let tight_loops: Vec<TightLoop> = features
        .iter()
        .filter_map(|f| match f {
            Feature::TightLoop(tl) => Some(*tl),
            _ => None,
        })
        .collect();
    let nzxors: Vec<VA> = features
        .iter()
        .filter_map(|f| match f {
            Feature::Nzxor(va) => Some(*va),
            _ => None,
        })
        .collect();
    let has_loop = features.iter().any(|f| matches!(f, Feature::Loop(_)));

    if !nzxors.is_empty() && has_loop {
        features.push(Feature::NzxorLoop);
    }
    for tl in tight_loops.iter() {
        for &xor in nzxors.iter() {
            if tl.start <= xor && xor <= tl.end {
                features.push(Feature::NzxorTightLoop);
            }
        }
    }
    if !tight_loops.is_empty() && f.blocks.len() < TIGHT_FUNCTION_MAX_BLOCKS {
        features.push(Feature::TightFunction);
    }

    features
}

/// `xor a, b` where a and b differ.
fn is_nonzeroing_xor(insn: &lancelot::analysis::dis::DecodedInstruction) -> bool {
    let ops = insn.visible_operands();
    ops.len() == 2 && ops[0].kind != ops[1].kind
}

/// is this xor part of a security cookie check?
/// they're near the start of the function, or the end of a returning block,
/// and use the stack or frame pointer.
fn is_security_cookie(
    ws: &Workspace,
    f: &Function,
    bb: &BasicBlock,
    va: VA,
    insn: &lancelot::analysis::dis::DecodedInstruction,
) -> bool {
    use zydis::Register as R;
    if let DecodedOperandKind::Reg(reg) = insn.visible_operands()[1].kind {
        if !matches!(reg, R::ESP | R::EBP | R::RSP | R::RBP) {
            return false;
        }
    }

    if bb.va == f.va && va < bb.va + SECURITY_COOKIE_BYTES_DELTA {
        return true;
    }

    let last = bb.last_insn();
    let ends_with_ret = ws
        .decode(last)
        .map(|i| i.mnemonic == zydis::Mnemonic::RET)
        .unwrap_or(false);
    let block_end = ws.decode(last).map(|i| last + i.length as u64).unwrap_or(last);
    ends_with_ret && va > block_end.saturating_sub(SECURITY_COOKIE_BYTES_DELTA)
}

/// `mov [reg], reg`: a register-dereferenced write to memory, with no displacement or index.
fn is_mov_via_register(insn: &lancelot::analysis::dis::DecodedInstruction) -> bool {
    let ops = insn.visible_operands();
    if ops.len() != 2 {
        return false;
    }
    if let DecodedOperandKind::Imm(_) = ops[1].kind {
        return false;
    }
    match &ops[0].kind {
        DecodedOperandKind::Mem(mem) => {
            mem.base != zydis::Register::NONE
                && mem.index == zydis::Register::NONE
                && (!mem.disp.has_displacement || mem.disp.displacement == 0)
        }
        _ => false,
    }
}

/// Estimate how many arguments the function takes.
///
/// vivisect does this with its calling convention analysis;
/// here we look for `ret N` and for reads of arguments on the stack via the frame pointer.
fn argument_count(ws: &Workspace, f: &Function) -> usize {
    use zydis::Register as R;
    match ws.arch() {
        Arch::X32 => {
            let mut count = 0usize;
            for va in f.insns() {
                let Some(insn) = ws.decode(va) else {
                    continue;
                };
                if insn.mnemonic == zydis::Mnemonic::RET {
                    if let Some(op) = insn.visible_operands().first() {
                        if let DecodedOperandKind::Imm(imm) = &op.kind {
                            count = count.max(imm.value as usize / 4);
                        }
                    }
                }
                for op in insn.visible_operands() {
                    if let DecodedOperandKind::Mem(mem) = &op.kind {
                        if mem.base == R::EBP && mem.index == R::NONE && mem.disp.displacement >= 8 {
                            count = count.max((mem.disp.displacement as usize - 8) / 4 + 1);
                        }
                    }
                }
            }
            count
        }
        Arch::X64 => {
            // which of the argument registers are read before they're written?
            let args = [R::RCX, R::RDX, R::R8, R::R9];
            let mut read: BTreeSet<usize> = Default::default();
            let mut written: BTreeSet<usize> = Default::default();
            let Some(entry) = f.blocks.get(&f.va) else {
                return 0;
            };
            for &va in entry.insns.iter() {
                let Some(insn) = ws.decode(va) else {
                    continue;
                };
                for op in insn.operands() {
                    let DecodedOperandKind::Reg(reg) = op.kind else {
                        continue;
                    };
                    let Some(i) = args.iter().position(|&a| reg.get_largest_enclosing(zydis::MachineMode::LONG_64) == a) else {
                        continue;
                    };
                    if op.action.intersects(zydis::OperandAction::MASK_READ) && !written.contains(&i) {
                        read.insert(i);
                    }
                    if op.action.intersects(zydis::OperandAction::MASK_WRITE) {
                        written.insert(i);
                    }
                }
            }
            read.iter().max().map(|&i| i + 1).unwrap_or(0)
        }
    }
}

/// strongly connected components of the block graph with two or more blocks.
/// returns the size of each loop.
fn find_loops(f: &Function) -> Vec<usize> {
    // Tarjan's algorithm, iteratively.
    let nodes: Vec<VA> = f.blocks.keys().copied().collect();
    let index_of: BTreeMap<VA, usize> = nodes.iter().enumerate().map(|(i, &va)| (va, i)).collect();
    let succs: Vec<Vec<usize>> = nodes
        .iter()
        .map(|va| {
            f.blocks[va]
                .successors
                .iter()
                .filter_map(|s| index_of.get(s).copied())
                .collect()
        })
        .collect();

    let n = nodes.len();
    let mut index = vec![usize::MAX; n];
    let mut lowlink = vec![0; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = vec![];
    let mut next_index = 0;
    let mut sizes = vec![];

    for root in 0..n {
        if index[root] != usize::MAX {
            continue;
        }
        // (node, next successor to visit)
        let mut work: Vec<(usize, usize)> = vec![(root, 0)];
        index[root] = next_index;
        lowlink[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;

        while let Some(&mut (v, ref mut i)) = work.last_mut() {
            if *i < succs[v].len() {
                let w = succs[v][*i];
                *i += 1;
                if index[w] == usize::MAX {
                    index[w] = next_index;
                    lowlink[w] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    work.push((w, 0));
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(index[w]);
                }
            } else {
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    lowlink[parent] = lowlink[parent].min(lowlink[v]);
                }
                if lowlink[v] == index[v] {
                    let mut size = 0;
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w] = false;
                        size += 1;
                        if w == v {
                            break;
                        }
                    }
                    if size >= 2 {
                        sizes.push(size);
                    }
                }
            }
        }
    }
    sizes
}

/// Find tight loops (algorithm by Blaine S.):
///
/// A) a block that conditionally loops to itself:
///
/// ```text
///         |
///         v v--+
///       [ a ]  |
///       /   \--+
///    [ b ]
/// ```
///
/// B) a block that conditionally branches to a block that loops back to it:
///
/// ```text
///         |
///         v v----+
///       [ a ]    |
///       /   \    |
///    [ b ] [ c ] |
///             \--+
/// ```
///
/// ignoring loops that call functions, or don't write memory.
pub fn find_tight_loops(ws: &Workspace, f: &Function) -> Vec<TightLoop> {
    let mut has_predecessor: BTreeSet<VA> = Default::default();
    for bb in f.blocks.values() {
        has_predecessor.extend(bb.successors.iter().copied());
    }

    let mut loops = vec![];
    for bb in f.blocks.values() {
        // skip the first and last blocks.
        if !has_predecessor.contains(&bb.va) || bb.successors.is_empty() {
            continue;
        }
        if bb.successors.len() != 2 {
            continue;
        }

        let mut loop_bb: Option<&BasicBlock> = None;
        let mut very_tight = false;
        if bb.successors.contains(&bb.va) {
            very_tight = true;
            loop_bb = Some(bb);
        } else {
            for succ in bb.successors.iter() {
                let Some(s) = f.blocks.get(succ) else {
                    continue;
                };
                if s.successors.contains(&bb.va) && (s.successors.len() == 1 || s.va == bb.va) {
                    loop_bb = Some(s);
                    break;
                }
            }
        }
        let Some(loop_bb) = loop_bb else {
            continue;
        };

        let Some(&next) = bb.successors.iter().find(|&&s| s != loop_bb.va) else {
            continue;
        };

        if contains_call(ws, bb) || contains_call(ws, loop_bb) {
            continue;
        }
        if !(writes_memory(ws, bb) || writes_memory(ws, loop_bb)) {
            continue;
        }

        loops.push(TightLoop {
            start: bb.va,
            end: next,
            very_tight,
        });
    }
    loops
}

fn contains_call(ws: &Workspace, bb: &BasicBlock) -> bool {
    bb.insns
        .iter()
        .any(|&va| ws.decode(va).map(|i| i.mnemonic == zydis::Mnemonic::CALL).unwrap_or(false))
}

fn writes_memory(ws: &Workspace, bb: &BasicBlock) -> bool {
    bb.insns.iter().any(|&va| {
        ws.decode(va)
            .and_then(|i| i.visible_operands().first().map(|op| matches!(op.kind, DecodedOperandKind::Mem(_))))
            .unwrap_or(false)
    })
}

/// the functions to emulate as decoding routines:
/// the `count` highest scoring, plus all tight functions.
pub fn select_decoding_functions(features: &BTreeMap<VA, FunctionFeatures>, count: usize) -> Vec<VA> {
    let mut ranked: Vec<&FunctionFeatures> = features.values().collect();
    // stable sort: ties keep address order, like FLOSS.
    ranked.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let mut selected: Vec<VA> = ranked.iter().take(count).map(|f| f.va).collect();
    for f in features.values() {
        if f.is_tight_function() && !selected.contains(&f.va) {
            selected.push(f.va);
        }
    }
    selected
}
