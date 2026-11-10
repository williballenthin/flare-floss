//! Instruction decoding, via zydis.
//!
//! floss-rs decodes instructions itself, from the bytes of the program or of the
//! emulator's memory, so that this doesn't depend on the backend that analyzed the program.
use std::sync::LazyLock;

pub use zydis::{self, ffi::DecodedOperandKind, Mnemonic, Register};

use crate::program::{Arch, VA};

pub type Instruction = zydis::Instruction<zydis::AllOperands>;

/// the longest x86 instruction.
pub const MAX_INSN_SIZE: usize = 15;

fn get_decoder(mode: zydis::MachineMode, stack_width: zydis::StackWidth) -> zydis::Decoder {
    use zydis::DecoderMode as D;

    let mut decoder = zydis::Decoder::new(mode, stack_width).expect("valid decoder mode");
    for mode in [D::MINIMAL, D::KNC, D::MPX, D::CET, D::LZCNT, D::TZCNT, D::WBNOINVD, D::CLDEMOTE] {
        decoder.enable_mode(mode, false).expect("valid decoder mode");
    }
    decoder
}

static DECODER32: LazyLock<zydis::Decoder> =
    LazyLock::new(|| get_decoder(zydis::MachineMode::LEGACY_32, zydis::StackWidth::_32));
static DECODER64: LazyLock<zydis::Decoder> =
    LazyLock::new(|| get_decoder(zydis::MachineMode::LONG_64, zydis::StackWidth::_64));

/// decode the instruction at the start of `buf`.
pub fn decode(arch: Arch, buf: &[u8]) -> Option<Instruction> {
    let decoder = match arch {
        Arch::X32 => &*DECODER32,
        Arch::X64 => &*DECODER64,
    };
    decoder.decode_first(buf).ok().flatten()
}

/// the target of a direct, near branch or call, like `jmp 0x401000`, in the instruction at `va`.
pub fn branch_target(insn: &Instruction, va: VA) -> Option<VA> {
    let op = insn.operands().first()?;
    match op.kind {
        DecodedOperandKind::Imm(ref imm) if imm.is_relative => insn.calc_absolute_address(va, op).ok(),
        _ => None,
    }
}

pub fn is_ret(insn: &Instruction) -> bool {
    insn.mnemonic == Mnemonic::RET
}

/// the bytes of arguments that a `ret N` pops.
pub fn ret_cleanup(insn: &Instruction) -> Option<u16> {
    if !is_ret(insn) {
        return None;
    }
    match insn.visible_operands().first()?.kind {
        DecodedOperandKind::Imm(ref imm) => Some(imm.value as u16),
        _ => None,
    }
}
