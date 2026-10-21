# floss-rs: evaluation

Can FLOSS be ported to Rust, using icicle for emulation, without losing what
makes FLOSS useful? This document collects the evidence. See
[DESIGN.md](DESIGN.md) for how floss-rs works.

**Short answer: yes.** floss-rs passes every FLOSS test case (including one that
FLOSS itself marks as an expected failure), finds strings that FLOSS misses,
runs 20-100x faster, and icicle's x86 semantics match QEMU's on 99.9% of
instructions sampled from real malware. The gaps are known and bounded.

## Setup

  - Python FLOSS: upstream `mandiant/flare-floss` at v4.0.0a2 (2026-10-21), vivisect 1.3.2,
    run without FLIRT signatures (`--signatures` with an empty directory),
    cache disabled, `--string-type stack tight decoded`.
  - floss-rs: this directory, release build, defaults (no FLIRT signatures,
    2 second time budget for decoding routines) unless noted.
  - Corpora:
      - the FLOSS test files (`mandiant/flare-floss-testfiles`): 43 Windows binaries
        and shellcode with expected strings, plus 5 other samples;
      - `tests/programs`: 24 builds of 6 small programs that exercise cases FLOSS misses;
      - 315 PE files from `mandiant/capa-testfiles` under 1.5MB (290 native, 25 .NET),
        and a random subset of 40 native files for comparison with Python FLOSS;
      - the largest native PEs in capa-testfiles (3-9.6MB), for scaling.
  - Machine: 4 cores, 15GB RAM; one process at a time per run.

## Correctness

### The FLOSS test suite

FLOSS's own test criterion: every expected string is found (as a stack, tight,
or decoded string).

| | passes | time (48 files) |
|---|---|---|
| Python FLOSS | 42 / 43 (fails `decode-global-stackstrings64`, marked `Xfail`) | 719s |
| floss-rs | **43 / 43** | 20-30s |

Beyond the expected strings, the differences from Python FLOSS on these files
are all fragments or junk that Python reports and floss-rs doesn't:
`hell` and `o world` (pieces of `hello world`), `idmm` and `n!vnsme` (pieces
of the encoded string), and `O0aA|A@`-like pointers. floss-rs additionally
finds `goodbye world` (a string built in global memory) and `LoadLibraryA`
(decoded on the heap in the real-world stack strings sample).

Per phase, averaged over the test binaries:

| phase | Python FLOSS | floss-rs | |
|---|---|---|---|
| program analysis (vivisect / lancelot, incl. SLEIGH compile) | 4.88s | 0.35s | 14x |
| stack strings | 2.46s | 0.027s | 91x |
| tight strings | 0.35s | 0.002s | 155x |
| decoded strings | 7.09s | 0.30s | 24x (floss-rs also emulates extra candidates) |
| total | 14.9s | 0.69s | 22x |

### Cases FLOSS misses (`tests/programs`)

Each program is built for x86 and x64, at -O0 and -O2, with clang and lld:

| program | what it does | Python FLOSS | floss-rs |
|---|---|---|---|
| `utf16-decode` | xor-decodes a UTF-16 string into a zeroed heap buffer | 0 / 4 | 4 / 4 |
| `overlap-decode` | decodes in place; some characters don't change | 0 / 4 | 4 / 4 |
| `global-stackstring` | builds a string in a global buffer | 2 / 4 | 4 / 4 |
| `inline-decode` | decoding loop inlined into the entry point, into a global | 0 / 4 | 4 / 4 |
| `wide-stackstring` | UTF-16 stack string | 4 / 4 | 4 / 4 |
| total | | **6 / 20** | **20 / 20** |

What makes the difference (see DESIGN.md):

  - reporting strings that *overlap* changed memory, rather than strings made of
    changed bytes (UTF-16 into zeroed memory; in-place decoding);
  - diffing global memory during stack string extraction;
  - emulating candidate routines that nothing calls from their entry;
  - counting calls to a thunk as calls to its target (x64 -O2 starts `decode`
    with a jump into its rotated loop, which looks like a thunk).

A sixth program, `reused-buffer`, checks the cost of reporting whole strings:
a decoder called twice writes the same string in front of different leftovers
(`secret key-xyz`, `secret key+abc`), and floss-rs reports it once.

### Real malware: robustness

floss-rs on all 315 capa test files under 1.5MB:

  - every file completes; there are no crashes or hangs;
  - .NET assemblies (25) and one PE with a malformed exception directory
    (which lancelot rejects) get static strings only, with a warning, like FLOSS for .NET;
  - mean 2.3s per file, max 15s (with the 2s decoding budget; 1.4s mean without it);
  - 240M instructions emulated, 6.4M snapshots, 1.6M API calls;
  - self-modifying code was handled (icicle's code cache flushed) 36 times.

On the largest files:

| file | size | functions | time | peak memory |
|---|---|---|---|---|
| `4122acca…` | 3.0MB | 1,446 | 8.3s | 398MB |
| `ed888dc2…` | 4.7MB | 63 | 1.0s | 61MB |
| `0761142e…` | 9.1MB | 1,467 | 16.8s | 424MB |
| `112f9f0e…` | 9.6MB | 12,819 | 88.7s | 1,026MB |

### Real malware: compared with Python FLOSS

Python FLOSS and floss-rs on 40 native files picked at random from the capa corpus:

| | novel strings | shared | only this one | total time | per file |
|---|---|---|---|---|---|
| Python FLOSS | 1,111 | | 179 (vs. budget 0), 168 (vs. defaults) | 9,102s (2.5 hours) | mean 228s, max 1,183s |
| floss-rs, `--time-budget 0` (FLOSS's candidates) | 1,057 | 932 | 125 | 67s | 95x faster (median; 13-280x) |
| floss-rs, defaults (2s budget) | 1,540 | 943 | 597 | 109s | 54x faster (median; 7-178x) |

The comparison counts only *novel* strings: strings that don't appear verbatim
(ASCII or UTF-16LE) in the file. A plain `strings` finds the rest, so they say
nothing about deobfuscation. (Python FLOSS reports many static strings as
"decoded": for example, it models `_vsnprintf` as `snprintf` because its hooks
match names by substring, and so "decodes" every format string passed to an
`snprintf` wrapper.)

The 168 novel strings that only Python FLOSS reports (against the defaults) are:

  - 83 pieces of strings that floss-rs reports whole: FLOSS extracts strings from
    changed bytes, so a decoded `cmd.exe /c net stop MSSQL$SYSTEM_BGC /y` also
    comes out as `e /c net stop MSSQL$SYSTEM_BGC /y` and `cmd.exe /c net sto`;
  - 23 emulator artifacts: `ineIntel` and `ntelineI` (vivisect's emulated `CPUID`),
    the fill byte as text (`fefefefe`), pieces of the emulated module path;
  - 15 static strings with junk in front (`KA\nss3.dll`, `@\Google\Chrome\User Data\Default\Login Data`);
  - 47 others, all junk on inspection: short random runs (`_o1VAo1`, `TUTUTUTU`),
    numbers formatted from uninitialized values (`Unknown error (1096175631)`),
    and fragments like `wRtlGe` and `omputerNameW`.

With `--time-budget 0`, the only plausibly real string of these is a fragment
of an API name, `teToolhelp32Snapshot`; with the default budget, floss-rs finds
it (whole) too.

The strings only floss-rs finds include `net stop` service lists in full
(27 commands), antivirus driver names (`avipbb.sys`, `cmdhlp.sys`), Task
Scheduler and registry configuration keys, and key material. They also
include noise, like intermediate states of decoders (`w1X1_1\1V1C1`) and
crypto tables built at run time. Most of the extra strings, and most of the
noise, come from emulating more candidates.

### Emulating more candidates

FLOSS emulates the 20 highest-scoring candidate decoding routines (plus tight
functions); with Python's speed, that's a necessary limit. On the 308 native
capa files, emulating more candidates for up to 2 seconds per file finds 60%
more novel strings (4,171 → 6,694) for 68% more total time (429s → 721s).
Among them, more ransom note text (strings containing `.onion`: 15 vs 7) and
more shadow copy deletion commands (`vssadmin delete shadows`: 5 vs 3;
`wmic shadowcopy delete`: 3 vs 2).
So floss-rs emulates at least the top 20, then keeps going, highest score first,
until decoding has taken 2 seconds (`--time-budget`), and tells the user.
`--time-budget 0` reproduces FLOSS's fixed set.

## icicle

### Fit

icicle is a Rust emulator built for fuzzing, MIT/Apache-2.0 licensed. It
decodes and lifts instructions with Ghidra's SLEIGH specifications (Apache-2.0),
and interprets the p-code (or JITs it with cranelift). FLOSS needs:

| need | icicle |
|---|---|
| x86 and x64 user-mode instruction semantics | yes: Ghidra's specs; see the differential testing below |
| execute one instruction at a time, inspect state between | yes: `Vm::step(1)`, ~0.2µs |
| save and restore state, cheaply, many times | memory: copy-on-write snapshots, ~2µs. registers: icicle copies a 128KB register file; floss-rs copies the used slots instead |
| compare memory before and after | snapshots expose their pages, so unchanged (shared) pages can be skipped |
| keep going after wild memory accesses | yes: an I/O memory region over unused address space (the "void") |
| handle faults and keep exploring other paths | yes: faults are exits with a code and address |
| intercept API calls | done in floss-rs (stubs), no icicle support needed |
| a permissive license | yes |
| no Ghidra installation | the specs (1.9MB) are embedded, and compiled at startup in ~0.3s |

### Differential testing against Unicorn

`examples/difftest.rs` collects unique, non-control-flow instructions from 60
capa test files (124k instructions; 248k cases, each with random registers,
flags, and SSE registers), runs each with icicle, and `scripts/difftest_unicorn.py`
runs the same cases with Unicorn (QEMU) and compares registers, flags, SSE
registers, and memory. (Unicorn is GPL; it's only a test oracle here.)

Of 186,338 cases that ran on both (62k faulted in both, from random pointers),
**186,173 match (99.91%)**, after excluding the AF flag. The differences
(`scripts/difftest-report.txt`):

| difference | cases | matters for FLOSS? |
|---|---|---|
| AF isn't computed by arithmetic instructions (Ghidra's SLEIGH: "AF not implemented") | all arithmetic | no: only BCD instructions and `pushf` read it |
| `div`/`idiv` don't raise #DE when the quotient overflows | 68 | no |
| `pcmpistri`, `psraw` (immediate form), `sysret` aren't implemented | 18 | rarely: `pcmpistri` is in optimized `strlen` |
| `cvttsd2si`/`cvttss2si` saturate instead of returning the "integer indefinite" value | 10 | no |
| 32-bit `xchg` with memory doesn't zero the upper half of RAX (x64) | 16 | rarely |
| MXCSR starts at 0, not 0x1f80 | 14 | no; floss-rs sets it |
| `aam`/`aad` flags, `push`/`pop` of segment registers | 32 | no |

Excluded from the test: control flow (tested by the FLOSS tests),
system instructions, x87, and VEX/EVEX encodings (Unicorn's QEMU doesn't support AVX).

### What real malware runs into

Across the capa corpus, the instructions icicle couldn't emulate were
(after floss-rs's additions): AVX (`vpand`, `vpshufb`, ...), `pcmpistri`,
`aesenc`, some x87 (`fyl2x`), and junk (16-bit addressing, `outs`, `arpl`) from
executing data. floss-rs implements `pshufb` (the most common) and makes
`xgetbv` report that AVX is disabled, so C runtime code takes non-AVX paths.
An unsupported instruction is skipped during exploration (as vivisect does)
and ends the run when emulating a decoder.

### Performance characteristics

  - **Lifting is the main cost.** Decoding and lifting an instruction with SLEIGH
    costs several microseconds; with icicle's lift-time optimizer on, ~30µs.
    FLOSS emulates most code once, so floss-rs disables the optimizer and the JIT
    (3-7x faster on larger files). Exploring every function of three capa files:
    7.5-10.6µs per instruction cold (lifting), 2.4-3.7µs warm (lifted code
    cached), of which roughly a third is snapshots at branches.
  - **vivisect, on the same exploration**: 1,541µs per instruction (021f49…:
    18k instructions in 27.9s vs floss-rs's 20k in 0.18s, ~170x).
  - **Snapshots**: memory ~2µs, plus registers; snapshot + restore ~4µs together.
  - **SLEIGH compilation**: 0.2-0.4s at startup, every run.

### Gaps and workarounds

| gap | workaround in floss-rs | could be fixed in icicle |
|---|---|---|
| self-modifying code: writes to lifted code fault, and changed bytes at a lifted address fault forever (the disassembly cache survives snapshot restores), even for bytes the lifter only read ahead | flush the code cache and retry | yes: make the disassembly check optional |
| CPU snapshots copy a 128KB register file | copy the used register slots | yes |
| memory snapshots keep their parent alive (unused) | none needed so far | yes: drop `parent` |
| stepping off a breakpoint doesn't advance | use `step(1)`, no breakpoints | — |
| `hlt` loops forever (Ghidra's semantics) | treat as a trap | — |
| user-ops without implementations (AVX, SSE4.2 strings, AES) | implement `pshufb`, report no AVX | yes, or in SLEIGH |
| specs must be files on disk | embed and write to a temp directory | an API to compile from memory (sleigh-compile has one) |

### Alternatives

There's no other mature, permissively licensed x86 emulator library:
Unicorn and Qiling are GPL; Bochs is LGPL; Triton (Apache-2.0) is a C++
symbolic execution framework; Ghidra's own p-code emulators are Java (or C++ in
the decompiler library); zyemu (MIT, Zydis-based) is early; lancelot's own Zydis-based emulator
is a prototype (14 mnemonics). Writing x86 semantics by hand is a large, ongoing
job that SLEIGH has already done.
icicle's design (SLEIGH semantics, Rust, copy-on-write snapshots) fits FLOSS well.

## What's not here (yet)

  - **ELF and Mach-O**: lancelot loads PE, COFF, and shellcode. FLOSS uses vivisect for ELF.
  - **Language-specific strings** (Go, Rust), **layout-aware static strings and tags**,
    rendering (FLOSS's text and HTML output), result caching: not ported;
    these don't involve emulation.
  - **FLIRT** works, but is opt-in (`--signatures`): loading FLOSS's signatures
    costs ~5s. Without FLIRT, statically linked library functions like `memcpy`
    are emulated rather than modeled.
  - **Calling conventions** for functions in the program come from `ret N`;
    vivisect does more analysis.
  - **Return address repair**: FLOSS's `ApiMonitor` recovers when a decoder
    returns to an unexpected address; floss-rs doesn't.
  - **Parallelism**: stack and tight strings run on several threads (one emulator
    each) for large files; decoded strings don't yet.
