//! print features of each candidate decoding routine, as JSON lines, to study which ones
//! predict that a routine decodes strings (see scripts/budget/).
//! besides FLOSS's features, these describe how the function is called (what its callers pass,
//! and what they do with the result) and what its loops do.
//! usage: candidate_features <pe>
use std::collections::{BTreeMap, BTreeSet, HashMap};

use floss::workspace::{Function, Workspace};
use lancelot::{
    analysis::dis::{zydis, DecodedOperandKind},
    arch::Arch,
    aspace::AddressSpace,
    VA,
};
use zydis::{Mnemonic as M, Register as R};

/// what a pointer points to.
#[derive(Debug, PartialEq)]
enum Pointee {
    /// a printable string, so the program's own static text.
    Text,
    /// zeros, like an output buffer in .bss.
    Zeros,
    /// other data in the image, which may be encoded.
    Data,
    /// code.
    Code,
}

fn classify(ws: &Workspace, p: VA) -> Option<Pointee> {
    let section = ws.module().sections.iter().find(|s| s.virtual_range.contains(&p))?;
    if section.permissions.intersects(lancelot::module::Permissions::X) && section.name != ".data" {
        return Some(Pointee::Code);
    }
    let buf = ws.module().address_space.read_bytes(p, 32).unwrap_or_default();
    if buf.is_empty() || buf.iter().all(|&b| b == 0) {
        return Some(Pointee::Zeros);
    }
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\r' || b == b'\n';
    let ascii = buf.iter().take_while(|&&b| printable(b)).count();
    let wide = buf.chunks(2).take_while(|c| c.len() == 2 && printable(c[0]) && c[1] == 0).count();
    let terminated = |n: usize, w: usize| buf.get(n * w).map(|&b| b == 0).unwrap_or(true);
    if (ascii >= 4 && terminated(ascii, 1)) || (wide >= 4 && terminated(wide, 2)) {
        return Some(Pointee::Text);
    }
    Some(Pointee::Data)
}

/// the import called by the instruction at `va`, directly (`call [iat]`) or via a thunk.
fn called_api(ws: &Workspace, imports: &HashMap<VA, String>, va: VA) -> Option<String> {
    let insn = ws.decode(va)?;
    if insn.mnemonic != M::CALL {
        return None;
    }
    let op = insn.visible_operands().first().cloned()?;
    let slot = match &op.kind {
        DecodedOperandKind::Mem(mem) if mem.base == R::RIP => insn.calc_absolute_address(va, &op).ok()?,
        DecodedOperandKind::Mem(mem) if mem.base == R::NONE && mem.index == R::NONE => mem.disp.displacement as u64,
        DecodedOperandKind::Imm(_) => {
            let target = insn.calc_absolute_address(va, &op).ok()?;
            if !ws.is_thunk(target) {
                return None;
            }
            return called_api(ws, imports, target).or_else(|| {
                let jmp = ws.decode(target)?;
                let op = jmp.visible_operands().first().cloned()?;
                match &op.kind {
                    DecodedOperandKind::Mem(mem) if mem.base == R::RIP => {
                        imports.get(&jmp.calc_absolute_address(target, &op).ok()?).cloned()
                    }
                    DecodedOperandKind::Mem(mem) if mem.base == R::NONE => imports.get(&(mem.disp.displacement as u64)).cloned(),
                    _ => None,
                }
            });
        }
        _ => return None,
    };
    imports.get(&slot).cloned()
}

/// APIs that take strings that a program would rather hide.
const STRING_APIS: &[&str] = &[
    "loadlibrary", "getprocaddress", "getmodulehandle", "regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue",
    "createfile", "createprocess", "shellexecute", "winexec", "internetopen", "internetconnect", "httpopenrequest",
    "httpsendrequest", "urldownloadtofile", "createmutex", "openmutex", "createservice", "openservice", "createdirectory",
    "deletefile", "copyfile", "movefile", "findfirstfile", "gethostbyname", "getaddrinfo", "connect", "send",
    "outputdebugstring", "messagebox", "createevent", "openevent", "createnamedpipe", "lstrcmp", "strcmp", "wcscmp",
    "strstr", "wcsstr", "lstrcpy", "lstrcat", "sprintf", "wsprintf",
];

fn is_string_api(name: &str) -> bool {
    let n = name.to_lowercase();
    STRING_APIS.iter().any(|a| n.starts_with(a) || n.trim_start_matches('_').starts_with(a))
}

/// the blocks of `f` that are in loops (strongly connected components of two or more blocks, or self loops).
fn loop_blocks(f: &Function) -> BTreeSet<VA> {
    // Tarjan, recursively: functions are small enough.
    struct T<'a> {
        f:       &'a Function,
        index:   HashMap<VA, usize>,
        low:     HashMap<VA, usize>,
        stack:   Vec<VA>,
        on:      BTreeSet<VA>,
        next:    usize,
        in_loop: BTreeSet<VA>,
    }
    fn visit(t: &mut T, v: VA) {
        t.index.insert(v, t.next);
        t.low.insert(v, t.next);
        t.next += 1;
        t.stack.push(v);
        t.on.insert(v);
        let succs = t.f.blocks.get(&v).map(|b| b.successors.clone()).unwrap_or_default();
        for w in succs.iter().copied().filter(|w| t.f.blocks.contains_key(w)) {
            if !t.index.contains_key(&w) {
                visit(t, w);
                let lw = t.low[&w];
                let lv = t.low.get_mut(&v).unwrap();
                *lv = (*lv).min(lw);
            } else if t.on.contains(&w) {
                let iw = t.index[&w];
                let lv = t.low.get_mut(&v).unwrap();
                *lv = (*lv).min(iw);
            }
        }
        if t.low[&v] == t.index[&v] {
            let mut scc = vec![];
            loop {
                let w = t.stack.pop().unwrap();
                t.on.remove(&w);
                scc.push(w);
                if w == v {
                    break;
                }
            }
            if scc.len() > 1 || succs.contains(&v) {
                t.in_loop.extend(scc);
            }
        }
    }
    let mut t = T {
        f,
        index: Default::default(),
        low: Default::default(),
        stack: vec![],
        on: Default::default(),
        next: 0,
        in_loop: Default::default(),
    };
    for &v in f.blocks.keys() {
        if !t.index.contains_key(&v) {
            visit(&mut t, v);
        }
    }
    t.in_loop
}

/// the functions that `fva` calls directly.
fn direct_callees(ws: &Workspace, fva: VA) -> Vec<VA> {
    let Some(f) = ws.function(fva) else { return vec![] };
    let mut out = vec![];
    for va in f.insns() {
        let Some(insn) = ws.decode(va) else { continue };
        if insn.mnemonic != M::CALL {
            continue;
        }
        let Some(op) = insn.visible_operands().first().cloned() else { continue };
        if let DecodedOperandKind::Imm(_) = op.kind {
            if let Ok(target) = insn.calc_absolute_address(va, &op) {
                if ws.function(target).is_some() && !ws.is_thunk(target) {
                    out.push(target);
                }
            }
        }
    }
    out
}

fn is_stack_reg(r: R) -> bool {
    matches!(r, R::ESP | R::EBP | R::RSP | R::RBP)
}

/// what the callers pass to the function at each call site, and what they do with the result.
#[derive(Default)]
struct CallSites {
    sites:          usize,
    callers:        usize,
    data_ptr:       usize,
    text_ptr:       usize,
    zero_ptr:       usize,
    stack_ptr:      usize,
    small_imm:      usize,
    api_after:      usize,
    string_api_after: usize,
}

fn call_sites(ws: &Workspace, imports: &HashMap<VA, String>, fva: VA) -> CallSites {
    let mut out = CallSites::default();
    let mut callers = BTreeSet::new();
    for site in ws.callers(fva) {
        out.sites += 1;
        let Some(caller) = ws.function_containing(site).and_then(|c| ws.function(c)) else {
            continue;
        };
        callers.insert(caller.va);
        let Some(bb) = caller.blocks.values().find(|bb| bb.insns.contains(&site)) else {
            continue;
        };
        let i = bb.insns.iter().position(|&va| va == site).unwrap();

        // the argument setup: the instructions since the previous call in this block, up to 12.
        let mut kinds = BTreeSet::new();
        let mut small = false;
        let before: Vec<VA> = bb.insns[..i].iter().rev().take(12).copied().collect();
        for &va in before.iter() {
            let Some(insn) = ws.decode(va) else { continue };
            if insn.mnemonic == M::CALL {
                break;
            }
            let ops = insn.visible_operands();
            let is_arg = match ws.arch() {
                Arch::X32 => insn.mnemonic == M::PUSH,
                Arch::X64 => {
                    matches!(insn.mnemonic, M::MOV | M::LEA)
                        && matches!(ops.first().map(|o| &o.kind), Some(DecodedOperandKind::Reg(r))
                            if matches!(r.largest_enclosing(zydis::MachineMode::LONG_64), R::RCX | R::RDX | R::R8 | R::R9))
                }
            } || (matches!(ws.arch(), Arch::X32) && matches!(insn.mnemonic, M::MOV | M::LEA));
            if !is_arg {
                continue;
            }
            let Some(src) = ops.last().cloned() else { continue };
            let value = match &src.kind {
                DecodedOperandKind::Imm(imm) => Some(imm.value),
                DecodedOperandKind::Mem(mem) if insn.mnemonic == M::LEA && mem.base == R::RIP => {
                    insn.calc_absolute_address(va, &src).ok()
                }
                DecodedOperandKind::Mem(mem) if insn.mnemonic == M::LEA && is_stack_reg(mem.base) => {
                    kinds.insert("stack");
                    None
                }
                DecodedOperandKind::Mem(mem) if insn.mnemonic == M::LEA && mem.base == R::NONE => {
                    Some(mem.disp.displacement as u64)
                }
                _ => None,
            };
            if let Some(v) = value {
                match classify(ws, v) {
                    Some(Pointee::Data) => {
                        kinds.insert("data");
                    }
                    Some(Pointee::Text) => {
                        kinds.insert("text");
                    }
                    Some(Pointee::Zeros) => {
                        kinds.insert("zeros");
                    }
                    Some(Pointee::Code) => {}
                    None if (1..=0x1000).contains(&v) => small = true,
                    None => {}
                }
            }
        }
        out.data_ptr += kinds.contains("data") as usize;
        out.text_ptr += kinds.contains("text") as usize;
        out.zero_ptr += kinds.contains("zeros") as usize;
        out.stack_ptr += kinds.contains("stack") as usize;
        out.small_imm += small as usize;

        // the result's use: an API call soon after, in this block or the next.
        let mut after: Vec<VA> = bb.insns[i + 1..].to_vec();
        if let Some(next) = bb.successors.first().and_then(|s| caller.blocks.get(s)) {
            after.extend(next.insns.iter().copied());
        }
        let apis: Vec<String> = after.iter().take(10).filter_map(|&va| called_api(ws, imports, va)).collect();
        out.api_after += !apis.is_empty() as usize;
        out.string_api_after += apis.iter().any(|a| is_string_api(a)) as usize;
    }
    out.callers = callers.len();
    out
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let buf = std::fs::read(&args[1])?;
    let ws = Workspace::from_pe(&buf, &[])?;
    let features = floss::features::find_decoding_function_features(&ws);
    let imports: HashMap<VA, String> = ws.imports().into_iter().map(|(va, stub)| (va, stub.name)).collect();

    for (fva, ff) in features.iter() {
        let f = ws.function(*fva).expect("candidate function");
        let in_loop = loop_blocks(f);
        let mut body: BTreeMap<&str, f64> = BTreeMap::new();
        for bb in f.blocks.values() {
            let looped = in_loop.contains(&bb.va);
            for &va in bb.insns.iter() {
                let Some(insn) = ws.decode(va) else { continue };
                let ops = insn.visible_operands();
                let mut c = |k: &'static str| *body.entry(k).or_insert(0.0) += 1.0;
                if insn.mnemonic == M::CALL {
                    c("calls_out");
                    if called_api(&ws, &imports, va).is_some() {
                        c("api_calls_out");
                    }
                }
                let byte_mem = ops.iter().any(|o| matches!(o.kind, DecodedOperandKind::Mem(_)) && o.size == 8);
                let byte_reg = ops.iter().any(|o| matches!(&o.kind, DecodedOperandKind::Reg(r) if r.width(zydis::MachineMode::LONG_COMPAT_32) == 8));
                let writes_mem = ops.first().map(|o| matches!(o.kind, DecodedOperandKind::Mem(_)) && o.action.intersects(zydis::OperandAction::MASK_WRITE)).unwrap_or(false);
                let arith = matches!(insn.mnemonic, M::XOR | M::ADD | M::SUB | M::NOT | M::NEG | M::ROL | M::ROR | M::SHL | M::SHR | M::IMUL | M::MUL | M::AND | M::OR);
                if byte_mem {
                    c("byte_mem");
                }
                if looped {
                    c("loop_insns");
                    if byte_mem {
                        c("loop_byte_mem");
                    }
                    if arith && (byte_reg || byte_mem) {
                        c("loop_byte_arith");
                    }
                    if arith {
                        c("loop_arith");
                    }
                    if writes_mem {
                        let base = match &ops[0].kind {
                            DecodedOperandKind::Mem(m) => m.base,
                            _ => R::NONE,
                        };
                        if !is_stack_reg(base) {
                            c("loop_ptr_writes");
                        }
                    }
                    if matches!(insn.mnemonic, M::XOR) && matches!(ops.last().map(|o| &o.kind), Some(DecodedOperandKind::Imm(_))) {
                        c("loop_xor_imm");
                    }
                }
            }
        }
        // what it calls: the same function over and over (like a decoder, once per string),
        // and functions with loops.
        let mut callees: BTreeMap<VA, usize> = BTreeMap::new();
        for va in f.insns() {
            let Some(insn) = ws.decode(va) else { continue };
            if insn.mnemonic != M::CALL {
                continue;
            }
            let Some(op) = insn.visible_operands().first().cloned() else { continue };
            if let DecodedOperandKind::Imm(_) = op.kind {
                if let Ok(target) = insn.calc_absolute_address(va, &op) {
                    if ws.function(target).is_some() && !ws.is_thunk(target) {
                        *callees.entry(target).or_insert(0) += 1;
                    }
                }
            }
        }
        let loopy = |t: &VA| ws.function(*t).map(|g| !loop_blocks(g).is_empty()).unwrap_or(false);
        body.insert("distinct_callees", callees.len() as f64);
        body.insert("max_calls_to_one", callees.values().copied().max().unwrap_or(0) as f64);
        body.insert("calls_to_loopy", callees.iter().filter(|(t, _)| loopy(t)).map(|(_, n)| *n).sum::<usize>() as f64);
        body.insert("max_calls_to_one_loopy", callees.iter().filter(|(t, _)| loopy(t)).map(|(_, n)| *n).max().unwrap_or(0) as f64);
        body.insert("no_callers", (ws.callers(*fva).count() == 0) as usize as f64);

        // what emulating it would reach, since emulation follows calls: the functions within two calls.
        let mut reach: BTreeSet<VA> = BTreeSet::new();
        let mut frontier: Vec<VA> = callees.keys().copied().collect();
        for _ in 0..2 {
            let mut next = vec![];
            for t in frontier {
                if t == *fva || !reach.insert(t) {
                    continue;
                }
                next.extend(direct_callees(&ws, t));
            }
            frontier = next;
        }
        body.insert("reach_functions", reach.len() as f64);
        body.insert("reach_loopy", reach.iter().filter(|t| loopy(t)).count() as f64);
        body.insert(
            "reach_insns",
            reach.iter().filter_map(|t| ws.function(*t)).map(|g| g.insns().count()).sum::<usize>() as f64,
        );
        let cs = call_sites(&ws, &imports, *fva);
        let mut row = serde_json::Map::new();
        row.insert("address".into(), (*fva).into());
        // FLOSS's score, which the study compares against (scripts/budget/).
        row.insert("score".into(), ff.floss_score.into());
        for (k, v) in ff.summary() {
            row.insert(k.into(), v.into());
        }
        for (k, v) in body {
            row.insert(k.into(), v.into());
        }
        row.insert("referenced_strings".into(), ws.referenced_strings(*fva).len().into());
        for (k, v) in [
            ("sites", cs.sites),
            ("callers", cs.callers),
            ("sites_data_ptr", cs.data_ptr),
            ("sites_text_ptr", cs.text_ptr),
            ("sites_zero_ptr", cs.zero_ptr),
            ("sites_stack_ptr", cs.stack_ptr),
            ("sites_small_imm", cs.small_imm),
            ("sites_api_after", cs.api_after),
            ("sites_string_api_after", cs.string_api_after),
        ] {
            row.insert(k.into(), v.into());
        }
        println!("{}", serde_json::Value::Object(row));
    }
    Ok(())
}
