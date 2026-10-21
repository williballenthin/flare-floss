"""run difftest cases with Unicorn (the oracle) and compare with icicle's results.

usage: difftest_unicorn.py cases.jsonl icicle.jsonl
"""
import sys, json, collections
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_ALL, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

CODE_BASE = 0x0100_0000
CODE_STRIDE = 0x20
DATA_BASE = 0x2000_0000
DATA_SIZE = 0x2_0000
CODE_SIZE = 0x80_0000

def data():
    x = 0x1234_5678_9abc_def1
    out = bytearray()
    M = (1 << 64) - 1
    for _ in range(DATA_SIZE):
        x ^= (x << 13) & M
        x ^= x >> 7
        x ^= (x << 17) & M
        out.append(x & 0xff)
    return bytes(out)

R32 = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI]
R64 = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
       UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
XMM = [UC_X86_REG_XMM0 + i for i in range(8)]
FLAGMASK = (0x8d5 | 0x400) & ~0x10  # CF PF ZF SF OF DF; AF: not implemented in Ghidra SLEIGH

DATA = data()
cases = [json.loads(l) for l in open(sys.argv[1])]
icicle = {o["id"]: o for o in map(json.loads, open(sys.argv[2]))}

ucs = {}
WRITES = []
def get_uc(bits):
    if bits not in ucs:
        uc = Uc(UC_ARCH_X86, UC_MODE_32 if bits == 32 else UC_MODE_64)
        uc.mem_map(CODE_BASE, CODE_SIZE, UC_PROT_ALL)
        uc.mem_map(DATA_BASE, DATA_SIZE, UC_PROT_ALL)
        uc.mem_write(DATA_BASE, DATA)
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda uc, access, addr, size, value, ud: WRITES.append((addr, size)))
        ucs[bits] = uc
    return ucs[bits]

stats = collections.Counter()
mismatch_by_mnem = collections.defaultdict(list)
for c in cases:
    uc = get_uc(c["bits"])
    regs = R32 if c["bits"] == 32 else R64
    WRITES.clear()
    code = bytes.fromhex(c["code"])
    pc = CODE_BASE + c["id"] * CODE_STRIDE
    uc.mem_write(pc, code + b"\xcc")
    uc.reg_write(UC_X86_REG_MXCSR, 0x1f80)
    for r, v in zip(regs, c["regs"]):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_EFLAGS, c["eflags"] | 0x2)
    for r, x in zip(XMM, c["xmm"]):
        uc.reg_write(r, int(x, 16))
    try:
        uc.emu_start(pc, pc + len(code), count=1)
        status = "ok"
    except UcError as e:
        status = "fault"

    ic = icicle.get(c["id"])
    if ic is None:
        stats["missing"] += 1
        continue
    # which data bytes changed, then restore them for the next case.
    written = sorted({a + i for a, n in WRITES for i in range(n) if DATA_BASE <= a + i < DATA_BASE + DATA_SIZE})
    umem = []
    for a in written:
        b = uc.mem_read(a, 1)[0]
        if b != DATA[a - DATA_BASE]:
            umem.append((a - DATA_BASE, b))
            uc.mem_write(a, DATA[a - DATA_BASE:a - DATA_BASE + 1])
    umem = umem[:64]
    # restore the code region to zeros.
    uc.mem_write(pc, bytes(len(code) + 1))
    for a, n in WRITES:
        if CODE_BASE <= a < CODE_BASE + CODE_SIZE:
            uc.mem_write(a, bytes(n))

    if status != "ok" or ic["status"] != "ok":
        if (status == "ok") != (ic["status"] == "ok"):
            stats["fault differs"] += 1
            mismatch_by_mnem[c["mnemonic"]].append((c["code"], f"unicorn {status}, icicle {ic['status']}"))
        else:
            stats["both fault"] += 1
        continue

    diffs = []
    names = ["ax","cx","dx","bx","sp","bp","si","di"] + [f"r{i}" for i in range(8,16)]
    for i, r in enumerate(regs):
        u = uc.reg_read(r)
        if u != ic["regs"][i]:
            diffs.append(f"{names[i]}: unicorn {u:#x} icicle {ic['regs'][i]:#x}")
    defined = FLAGMASK & ~c["undefined"]
    uf = uc.reg_read(UC_X86_REG_EFLAGS) & defined
    if uf != ic["eflags"] & defined:
        diffs.append(f"eflags: unicorn {uf:#x} icicle {ic['eflags'] & defined:#x} (defined {defined:#x})")
    for i, r in enumerate(XMM):
        u = uc.reg_read(r)
        if u != int(ic["xmm"][i], 16):
            diffs.append(f"xmm{i}: unicorn {u:#034x} icicle 0x{ic['xmm'][i]}")
    if [tuple(x) for x in ic["mem"]] != umem:
        diffs.append(f"memory: unicorn {umem[:4]} icicle {ic['mem'][:4]}")
    if diffs:
        stats["mismatch"] += 1
        mismatch_by_mnem[c["mnemonic"]].append((c["code"], "; ".join(diffs)))
    else:
        stats["match"] += 1

print(dict(stats))
print(f"{len(mismatch_by_mnem)} mnemonics with mismatches")
for m, items in sorted(mismatch_by_mnem.items(), key=lambda kv: -len(kv[1])):
    print(f"  {m}: {len(items)}  e.g. {items[0][0]}: {items[0][1][:220]}")
