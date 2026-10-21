//! Differential testing of icicle's x86 semantics.
//!
//! `difftest gen <cases.jsonl> <pe>...`
//!     collect unique, non-control-flow instructions from the given programs,
//!     and write test cases: the instruction and a few random initial states.
//!
//! `difftest run <cases.jsonl> <results.jsonl>`
//!     execute each case with icicle and write the final state.
//!
//! `scripts/difftest_unicorn.py` runs the same cases with Unicorn, and compares.
//! (Unicorn is GPL, so it's only used here, as a test oracle, outside the floss binary.)
use std::{
    collections::BTreeSet,
    io::{BufRead, Write},
};

use anyhow::{anyhow, Result};
use icicle_vm::cpu::mem::{perm, Mapping};
use lancelot::analysis::dis::{zydis, DecodedOperandKind};
use serde::{Deserialize, Serialize};

const CODE_BASE: u64 = 0x0100_0000;
const CODE_STRIDE: u64 = 0x20;
const DATA_BASE: u64 = 0x2000_0000;
const DATA_SIZE: u64 = 0x2_0000;
const STATES_PER_INSN: usize = 2;
/// room for 0x40000 cases.
const CODE_SIZE: u64 = 0x80_0000;

#[derive(Serialize, Deserialize, Clone)]
struct Case {
    id:        usize,
    bits:      u32,
    code:      String,
    mnemonic:  String,
    /// EFLAGS bits that the instruction leaves undefined.
    undefined: u32,
    regs:      Vec<u64>,
    eflags:    u32,
    /// xmm0-7, hex, little-endian.
    xmm:       Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Outcome {
    id:     usize,
    status: String,
    regs:   Vec<u64>,
    eflags: u32,
    pc:     u64,
    xmm:    Vec<String>,
    /// (offset, value) of data bytes that differ from the initial data.
    mem:    Vec<(u64, u8)>,
}

const GPRS_32: &[&str] = &["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"];
const GPRS_64: &[&str] = &[
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
];
const FLAGS: &[(&str, u32)] = &[("CF", 0), ("PF", 2), ("AF", 4), ("ZF", 6), ("SF", 7), ("DF", 10), ("OF", 11)];

/// the fixed initial contents of the data region.
fn data() -> Vec<u8> {
    let mut x: u64 = 0x1234_5678_9abc_def1;
    (0..DATA_SIZE)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn excluded(insn: &lancelot::analysis::dis::DecodedInstruction) -> bool {
    use zydis::{InstructionCategory as C, Mnemonic as M};
    if matches!(
        insn.meta.category,
        C::COND_BR
            | C::UNCOND_BR
            | C::CALL
            | C::RET
            | C::SYSTEM
            | C::SYSCALL
            | C::INTERRUPT
            | C::IO
            | C::IOSTRINGOP
            | C::X87_ALU
            | C::FCMOV
            | C::SEGOP
            | C::AVX
            | C::AVX2
            | C::AVX512
            | C::FMA4
            | C::AES
            | C::SHA
    ) {
        return true;
    }
    if matches!(
        insn.mnemonic,
        M::CPUID | M::RDTSC | M::RDTSCP | M::RDRAND | M::RDSEED | M::XGETBV | M::PUSHFD | M::PUSHFQ | M::PUSHF | M::POPF | M::POPFD | M::POPFQ | M::LOOP | M::LOOPE | M::LOOPNE | M::JCXZ | M::JECXZ | M::JRCXZ | M::ENTER | M::LEAVE | M::BOUND | M::LAHF | M::SAHF
    ) {
        return true;
    }
    if insn.encoding != zydis::InstructionEncoding::LEGACY {
        // VEX, EVEX, ... aren't supported by the version of QEMU in Unicorn.
        return true;
    }
    // segment overrides, like fs:[0x30]
    insn.operands().iter().any(|op| match &op.kind {
        DecodedOperandKind::Mem(mem) => matches!(mem.segment, zydis::Register::FS | zydis::Register::GS),
        DecodedOperandKind::Reg(r) => matches!(
            r,
            zydis::Register::CS | zydis::Register::DS | zydis::Register::ES | zydis::Register::FS | zydis::Register::GS | zydis::Register::SS
        ) && op.visibility == zydis::OperandVisibility::EXPLICIT,
        _ => false,
    })
}

fn gen(out: &str, paths: &[String]) -> Result<()> {
    let mut seen: BTreeSet<(u32, Vec<u8>)> = Default::default();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut id = 0;
    for path in paths {
        let Ok(buf) = std::fs::read(path) else { continue };
        let Ok(ws) = floss::workspace::Workspace::from_pe(&buf, &[]) else { continue };
        let bits = match ws.arch() {
            lancelot::arch::Arch::X32 => 32,
            lancelot::arch::Arch::X64 => 64,
        };
        let module = ws.module();
        for f_ in ws.functions() {
            for va in f_.insns() {
                let Some(insn) = ws.decode(va) else { continue };
                if excluded(&insn) {
                    continue;
                }
                let bytes = lancelot::aspace::AddressSpace::read_bytes(&module.address_space, va, insn.length as usize)?;
                if !seen.insert((bits, bytes.clone())) {
                    continue;
                }
                for _ in 0..STATES_PER_INSN {
                    let ngprs = if bits == 32 { 8 } else { 16 };
                    let regs: Vec<u64> = (0..ngprs)
                        .map(|i| {
                            let r = rng.next();
                            if i == 4 {
                                // the stack pointer: inside the data region.
                                return DATA_BASE + 0x1_0000 + (r % 0x100) * 8;
                            }
                            let v = match r % 10 {
                                0..=5 => DATA_BASE + 0x1000 + (rng.next() % (DATA_SIZE - 0x2000)),
                                6..=7 => rng.next() % 0x100,
                                _ => rng.next(),
                            };
                            if bits == 32 {
                                v & 0xffff_ffff
                            } else {
                                v
                            }
                        })
                        .collect();
                    let eflags = (rng.next() as u32) & 0x8d5; // CF PF AF ZF SF OF; DF clear
                    let xmm = (0..8)
                        .map(|_| format!("{:016x}{:016x}", rng.next(), rng.next()))
                        .collect();
                    let case = Case {
                        id,
                        bits,
                        code: bytes.iter().map(|b| format!("{b:02x}")).collect(),
                        mnemonic: insn.mnemonic.static_string().unwrap_or("?").to_string(),
                        undefined: insn.cpu_flags.undefined.bits(),
                        regs,
                        eflags,
                        xmm,
                    };
                    writeln!(f, "{}", serde_json::to_string(&case)?)?;
                    id += 1;
                }
            }
        }
    }
    eprintln!("{id} cases");
    Ok(())
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// xmm hex is big-endian (like "{:016x}{:016x}" of the high and low halves).
fn xmm_to_le(s: &str) -> Vec<u8> {
    let mut b = hex_to_bytes(s);
    b.reverse();
    b
}

fn xmm_from_le(b: &[u8]) -> String {
    b.iter().rev().map(|b| format!("{b:02x}")).collect()
}

fn run(cases_path: &str, out: &str) -> Result<()> {
    let cases: Vec<Case> = std::io::BufReader::new(std::fs::File::open(cases_path)?)
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    let data = data();
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);

    for bits in [32, 64] {
        let cases: Vec<&Case> = cases.iter().filter(|c| c.bits == bits).collect();
        if cases.is_empty() {
            continue;
        }
        let triple = if bits == 32 { "i686-none" } else { "x86_64-none" };
        let config = icicle_vm::cpu::Config {
            triple: triple.parse().unwrap(),
            enable_shadow_stack: false,
            enable_jit: false,
            optimize_instructions: false,
            optimize_block: false,
            ..Default::default()
        };
        let mut vm = icicle_vm::build_with_path(&config, &floss::emu::sleigh::processors_dir()?)
            .map_err(|e| anyhow!("{e}"))?;
        // each case has its own address, so there's no stale code to detect.
        vm.cpu.mem.detect_self_modifying_code = false;
        // the code region is zeros, except for the instruction under test.
        vm.cpu.mem.map_memory_len(CODE_BASE, CODE_SIZE, Mapping { perm: perm::READ | perm::WRITE | perm::EXEC | perm::INIT, value: 0 });
        vm.cpu.mem.map_memory_len(DATA_BASE, DATA_SIZE, Mapping { perm: perm::READ | perm::WRITE | perm::INIT, value: 0 });
        vm.cpu.mem.write_bytes(DATA_BASE, &data, perm::NONE).unwrap();
        let pristine = vm.snapshot();

        let names = if bits == 32 { GPRS_32 } else { GPRS_64 };
        let reg = |vm: &icicle_vm::Vm, n: &str| vm.cpu.arch.sleigh.get_reg(n).unwrap().get_var().unwrap();
        let gprs: Vec<_> = names.iter().map(|n| reg(&vm, n)).collect();
        let flags: Vec<_> = FLAGS.iter().map(|(n, bit)| (reg(&vm, n), *bit)).collect();
        let xmms: Vec<_> = (0..8).map(|i| reg(&vm, &format!("XMM{i}"))).collect();

        for c in cases {
            vm.restore(&pristine);
            for (var, &v) in gprs.iter().zip(c.regs.iter()) {
                vm.cpu.write_reg(*var, v);
            }
            for &(var, bit) in flags.iter() {
                vm.cpu.write_reg(var, ((c.eflags >> bit) & 1) as u64);
            }
            for (var, x) in xmms.iter().zip(c.xmm.iter()) {
                vm.cpu.regs.get_mut(*var).unwrap().copy_from_slice(&xmm_to_le(x));
            }
            let pc = CODE_BASE + c.id as u64 * CODE_STRIDE;
            // int3 ends the block, so icicle doesn't lift (and cache) the bytes after the instruction.
            let mut code = hex_to_bytes(&c.code);
            code.push(0xcc);
            vm.cpu.mem.write_bytes(pc, &code, perm::NONE).unwrap();
            vm.cpu.write_pc(pc);

            let exit = vm.step(1);
            let status = match exit {
                icicle_vm::VmExit::InstructionLimit => "ok".to_string(),
                icicle_vm::VmExit::UnhandledException((code, _)) => format!("{code:?}"),
                other => format!("{other:?}"),
            };

            let regs = gprs.iter().map(|v| vm.cpu.read_reg(*v)).collect();
            let eflags = flags.iter().map(|&(v, bit)| ((vm.cpu.read_reg(v) & 1) as u32) << bit).sum();
            let xmm = xmms.iter().map(|v| xmm_from_le(vm.cpu.regs.get(*v).unwrap())).collect();
            let mut buf = vec![0u8; DATA_SIZE as usize];
            vm.cpu.mem.read_bytes(DATA_BASE, &mut buf, perm::NONE).unwrap();
            let mem = buf
                .iter()
                .zip(data.iter())
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, (a, _))| (i as u64, *a))
                .take(64)
                .collect();
            let outcome = Outcome {
                id: c.id,
                status,
                regs,
                eflags,
                pc: vm.cpu.read_pc(),
                xmm,
                mem,
            };
            writeln!(f, "{}", serde_json::to_string(&outcome)?)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("gen") => gen(&args[2], &args[3..]),
        Some("run") => run(&args[2], &args[3]),
        _ => Err(anyhow!("usage: difftest gen <cases> <pe>... | difftest run <cases> <results>")),
    }
}
