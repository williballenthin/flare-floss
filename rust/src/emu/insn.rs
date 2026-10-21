//! Just enough instruction decoding to drive the emulator:
//! control flow, and a couple of properties the string heuristics care about.
//!
//! icicle executes the instruction semantics; this module only
//! classifies instructions, using zydis via lancelot.
use lancelot::{
    analysis::dis::{self, zydis, DecodedOperandKind},
    VA,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// falls through to the next instruction.
    Next,
    Call,
    Ret,
    /// unconditional jump, with its target when it's direct.
    Jump(Option<VA>),
    /// conditional jump (including `loop` and `jecxz`), with its target.
    CondJump(VA),
    /// an instruction that doesn't continue: `hlt`, `int3`, `ud2`, ...
    Trap,
    /// not an instruction: an import stub. "executing" it calls the API and returns.
    Api,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub va:   VA,
    pub len:  u8,
    pub flow: Flow,
    /// has a `rep`/`repe`/`repne` prefix.
    pub rep:  bool,
    /// a `mov`-family instruction that writes to memory via a register,
    /// like `mov [ebp-0x10], eax` or `movdqa [esp+0x20], xmm0`, or a string move like `movsb`.
    /// this is FLOSS's signal that a block might be constructing a stack string.
    pub is_mov_to_memory: bool,
}

impl Insn {
    /// the pseudo-instruction at an import stub.
    pub fn api(va: VA) -> Insn {
        Insn {
            va,
            len: 0,
            flow: Flow::Api,
            rep: false,
            is_mov_to_memory: false,
        }
    }

    pub fn next(&self) -> VA {
        self.va + self.len as u64
    }

    pub fn decode(decoder: &zydis::Decoder, va: VA, buf: &[u8]) -> Option<Insn> {
        let insn = dis::decode(decoder, buf).ok()??;

        use zydis::Mnemonic as M;
        let flow = match insn.mnemonic {
            M::CALL => Flow::Call,
            M::RET => Flow::Ret,
            M::JMP => Flow::Jump(branch_target(&insn, va)),
            M::JB
            | M::JBE
            | M::JCXZ
            | M::JECXZ
            | M::JRCXZ
            | M::JL
            | M::JLE
            | M::JNB
            | M::JNBE
            | M::JNL
            | M::JNLE
            | M::JNO
            | M::JNP
            | M::JNS
            | M::JNZ
            | M::JO
            | M::JP
            | M::JS
            | M::JZ
            | M::LOOP
            | M::LOOPE
            | M::LOOPNE => Flow::CondJump(branch_target(&insn, va)?),
            M::HLT | M::INT3 | M::INT | M::INT1 | M::INTO | M::UD0 | M::UD1 | M::UD2 | M::IRET | M::IRETD | M::IRETQ => {
                Flow::Trap
            }
            _ => Flow::Next,
        };

        let attrs = insn.attributes;
        let rep = attrs.intersects(
            zydis::InstructionAttributes::HAS_REP
                | zydis::InstructionAttributes::HAS_REPE
                | zydis::InstructionAttributes::HAS_REPNE,
        );

        Some(Insn {
            va,
            len: insn.length,
            flow,
            rep,
            is_mov_to_memory: is_mov_to_memory(&insn),
        })
    }
}

fn branch_target(insn: &dis::DecodedInstruction, va: VA) -> Option<VA> {
    let op = insn.operands().first()?;
    match op.kind {
        DecodedOperandKind::Imm(ref imm) if imm.is_relative => insn.calc_absolute_address(va, op).ok(),
        _ => None,
    }
}

/// see `Insn::is_mov_to_memory`.
/// this mirrors FLOSS's `StackstringContextMonitor.is_stack_mov`.
fn is_mov_to_memory(insn: &dis::DecodedInstruction) -> bool {
    let is_mov = insn
        .mnemonic
        .static_string()
        .map(|m| m.starts_with("mov"))
        .unwrap_or(false);
    if !is_mov {
        return false;
    }

    match insn.visible_operands().first() {
        // string moves, like `movsb`, have no explicit operands.
        // count these regardless of where data is moved to.
        None => true,
        Some(op) => match &op.kind {
            // a memory operand addressed by a register (not an absolute address).
            DecodedOperandKind::Mem(mem) => mem.base != zydis::Register::NONE || mem.index != zydis::Register::NONE,
            _ => false,
        },
    }
}
