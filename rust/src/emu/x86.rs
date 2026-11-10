//! Implementations of x86 instructions that Ghidra's SLEIGH specification
//! leaves to the emulator (as p-code "user operations"), and that icicle doesn't provide.
//!
//! The emulator's statistics (`Stats::unsupported`) show which ones matter:
//! across the capa test files, `pshufb` is the most common, from SIMD string routines.
//! AVX instructions are another gap; rather than implement them, `xgetbv` reports
//! that the OS hasn't enabled AVX, so code that checks (like the C runtime) avoids them.
//! AES-NI is here too: Rust's `aes` crate uses it when CPUID says it's there, like for
//! strings encrypted with AES-GCM (the obfuse crate).
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

/// the AES S-box, and its inverse, computed at compile time from the field arithmetic.
const SBOX: [u8; 256] = sbox();
const INV_SBOX: [u8; 256] = inverse(&SBOX);

/// multiply in GF(2^8), modulo x^8 + x^4 + x^3 + x + 1.
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    p
}

const fn sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        // the multiplicative inverse (0 for 0), then the affine transformation.
        let mut inv = 0u8;
        let mut y = 1;
        while x != 0 && y < 256 {
            if gmul(x as u8, y as u8) == 1 {
                inv = y as u8;
            }
            y += 1;
        }
        sbox[x] = inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63;
        x += 1;
    }
    sbox
}

const fn inverse(table: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[table[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// an AES state, as in an XMM register: byte `r + 4c` is row `r` of column `c`.
type Block = [u8; 16];

fn shift_rows(s: &Block, inverse: bool) -> Block {
    let mut out = [0; 16];
    for c in 0..4 {
        for r in 0..4 {
            let from = if inverse { (c + 4 - r) % 4 } else { (c + r) % 4 };
            out[r + 4 * c] = s[r + 4 * from];
        }
    }
    out
}

fn mix_columns(s: &Block, inverse: bool) -> Block {
    let m: [u8; 4] = if inverse { [14, 11, 13, 9] } else { [2, 3, 1, 1] };
    let mut out = [0; 16];
    for c in 0..4 {
        let col = &s[4 * c..4 * c + 4];
        for r in 0..4 {
            out[r + 4 * c] = (0..4).fold(0, |acc, i| acc ^ gmul(col[(r + i) % 4], m[i]));
        }
    }
    out
}

fn sub_bytes(s: &Block, table: &[u8; 256]) -> Block {
    s.map(|b| table[b as usize])
}

fn xor(a: &Block, b: &Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}

fn aes_round(state: &Block, key: &Block, decrypt: bool, last: bool) -> Block {
    let table = if decrypt { &INV_SBOX } else { &SBOX };
    let mut s = sub_bytes(&shift_rows(state, decrypt), table);
    if !last {
        s = mix_columns(&s, decrypt);
    }
    xor(&s, key)
}

/// `aeskeygenassist`: the S-box applied to the second and fourth dwords, each also rotated
/// and xored with the round constant.
fn aes_keygen_assist(src: &Block, rcon: u8) -> Block {
    let word = |i: usize| -> [u8; 4] { std::array::from_fn(|j| SBOX[src[4 * i + j] as usize]) };
    let (x1, x3) = (word(1), word(3));
    let rot = |w: [u8; 4]| -> [u8; 4] { [w[1] ^ rcon, w[2], w[3], w[0]] };
    let mut out = [0; 16];
    out[0..4].copy_from_slice(&x1);
    out[4..8].copy_from_slice(&rot(x1));
    out[8..12].copy_from_slice(&x3);
    out[12..16].copy_from_slice(&rot(x3));
    out
}

fn read_block(cpu: &mut Cpu, v: Value) -> Block {
    std::array::from_fn(|i| cpu.read::<u8>(v.slice(i as u8, 1)))
}

fn write_block(cpu: &mut Cpu, dst: VarNode, block: &Block) {
    for (i, &b) in block.iter().enumerate() {
        cpu.write_var(dst.slice(i as u8, 1), b);
    }
}

fn aesenc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let (s, k) = (read_block(cpu, args[0]), read_block(cpu, args[1]));
    write_block(cpu, dst, &aes_round(&s, &k, false, false));
}

fn aesenclast(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let (s, k) = (read_block(cpu, args[0]), read_block(cpu, args[1]));
    write_block(cpu, dst, &aes_round(&s, &k, false, true));
}

fn aesdec(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let (s, k) = (read_block(cpu, args[0]), read_block(cpu, args[1]));
    write_block(cpu, dst, &aes_round(&s, &k, true, false));
}

fn aesdeclast(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let (s, k) = (read_block(cpu, args[0]), read_block(cpu, args[1]));
    write_block(cpu, dst, &aes_round(&s, &k, true, true));
}

fn aesimc(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let s = read_block(cpu, args[0]);
    write_block(cpu, dst, &mix_columns(&s, true));
}

fn aeskeygenassist(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let s = read_block(cpu, args[0]);
    let rcon = cpu.read::<u8>(args[1].slice(0, 1));
    write_block(cpu, dst, &aes_keygen_assist(&s, rcon));
}

pub fn install(vm: &mut icicle_vm::Vm) {
    let helpers: [(&str, icicle_vm::cpu::exec::helpers::PcodeOpHelper); 8] = [
        ("pshufb", pshufb),
        ("xinuse", xinuse),
        ("aesenc", aesenc),
        ("aesenclast", aesenclast),
        ("aesdec", aesdec),
        ("aesdeclast", aesdeclast),
        ("aesimc", aesimc),
        ("aeskeygenassist", aeskeygenassist),
    ];
    for (name, helper) in helpers {
        if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
            vm.cpu.set_helper(id, helper);
        }
    }
    if let Some(xcr0) = vm.cpu.arch.sleigh.get_varnode("XCR0") {
        vm.cpu.write_reg(xcr0, XCR0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Block {
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    /// AES-128 key expansion, the way code does it with `aeskeygenassist`.
    fn expand(key: &Block) -> Vec<Block> {
        let mut keys = vec![*key];
        for rcon in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36] {
            let prev = *keys.last().unwrap();
            let assist = aes_keygen_assist(&prev, rcon);
            let t: [u8; 4] = assist[12..16].try_into().unwrap();
            let mut next = [0; 16];
            for w in 0..4 {
                for j in 0..4 {
                    let before = if w == 0 { t[j] } else { next[4 * (w - 1) + j] };
                    next[4 * w + j] = prev[4 * w + j] ^ before;
                }
            }
            keys.push(next);
        }
        keys
    }

    #[test]
    fn test_sbox() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(INV_SBOX[0x63], 0x00);
    }

    /// FIPS-197, appendix C.1: AES-128.
    #[test]
    fn test_aes128() {
        let keys = expand(&hex("000102030405060708090a0b0c0d0e0f"));
        assert_eq!(keys[10], hex("13111d7fe3944a17f307a78b4d2b30c5"));

        let plaintext = hex("00112233445566778899aabbccddeeff");
        let ciphertext = hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        let mut s = xor(&plaintext, &keys[0]);
        for (i, key) in keys.iter().enumerate().skip(1) {
            s = aes_round(&s, key, false, i == 10);
        }
        assert_eq!(s, ciphertext);

        // the equivalent inverse cipher, with aesimc'd round keys, as aesdec expects.
        let mut s = xor(&ciphertext, &keys[10]);
        for i in (0..10).rev() {
            let key = if i == 0 { keys[0] } else { mix_columns(&keys[i], true) };
            s = aes_round(&s, &key, true, i == 0);
        }
        assert_eq!(s, plaintext);
    }
}
