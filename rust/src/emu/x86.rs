//! Implementations of x86 instructions that Ghidra's SLEIGH specification
//! leaves to the emulator (as p-code "user operations"), and that icicle doesn't provide.
//!
//! The emulator's statistics (`Stats::unsupported`) show which ones matter:
//! across the capa test files, `pshufb` is the most common, from SIMD string routines.
//! AVX instructions are another gap; rather than implement them, `xgetbv` reports
//! that the OS hasn't enabled AVX, so code that checks (like the C runtime) avoids them.
use icicle_vm::cpu::{Cpu, ValueSource};
use pcode::{Value, VarNode};

/// the XCR0 register: x87 and SSE state enabled, AVX not.
const XCR0: u64 = 0b11;

/// `pshufb dst, src`: shuffle the bytes of `dst` using the indexes in `src`;
/// an index with its high bit set selects zero. for MMX (8 bytes) and SSE (16 bytes) registers.
fn pshufb(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let n = dst.size as usize;
    let read = |cpu: &mut Cpu, v: Value| -> Vec<u8> { (0..n).map(|i| cpu.read::<u8>(v.slice(i as u8, 1))).collect() };
    let data = read(cpu, args[0]);
    let indexes = read(cpu, args[1]);
    for (i, &index) in indexes.iter().enumerate() {
        let value = if index & 0x80 != 0 { 0 } else { data[index as usize & (n - 1)] };
        cpu.write_var(dst.slice(i as u8, 1), value);
    }
}

/// used by `xgetbv`: which processor state components are in use (here: the enabled ones).
fn xinuse(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
    cpu.write_var(dst, XCR0);
}

pub fn install(vm: &mut icicle_vm::Vm) {
    for (name, helper) in [("pshufb", pshufb as icicle_vm::cpu::exec::helpers::PcodeOpHelper), ("xinuse", xinuse)] {
        if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
            vm.cpu.set_helper(id, helper);
        }
    }
    if let Some(xcr0) = vm.cpu.arch.sleigh.get_varnode("XCR0") {
        vm.cpu.write_reg(xcr0, XCR0);
    }
}
