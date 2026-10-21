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
    5 second time budget for decoding routines, threads for each CPU) unless noted.
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
  - mean 1.9s per file, max 10.3s (with the 5s decoding budget and 4 threads; 1.2s mean without the budget);
  - 517M instructions emulated, 11.7M snapshots, 3.7M API calls;
  - self-modifying code was handled (icicle's code cache flushed) 89 times.

On the largest files:

| file | size | functions | time | peak memory |
|---|---|---|---|---|
| `4122acca…` | 3.0MB | 1,446 | 10.2s | 1,004MB |
| `ed888dc2…` | 4.7MB | 63 | 0.5s | 60MB |
| `0761142e…` | 9.1MB | 1,467 | 19.6s | 1,012MB |
| `112f9f0e…` | 9.6MB | 12,819 | 37.6s | 1,664MB |

Each thread has its own emulator, which holds the code it has lifted: about 200MB
per thread for a program of 1,400 functions. `--threads` limits it.

### Real malware: compared with Python FLOSS

Python FLOSS and floss-rs on 40 native files picked at random from the capa corpus:

| | novel strings | shared | only this one | total time | per file |
|---|---|---|---|---|---|
| Python FLOSS | 1,111 | | 180 (vs. budget 0), 163 (vs. defaults) | 9,102s (2.5 hours) | mean 228s, max 1,183s |
| floss-rs, `--time-budget 0` (FLOSS's candidates) | 1,053 | 931 | 122 | 54s | 109x faster (median; 31-371x) |
| floss-rs, defaults (5s budget, 4 threads) | 2,019 | 948 | 1,071 | 96s | 69x faster (median; 26-181x) |

The comparison counts only *novel* strings: strings that don't appear verbatim
(ASCII or UTF-16LE) in the file. A plain `strings` finds the rest, so they say
nothing about deobfuscation. (Python FLOSS reports many static strings as
"decoded": for example, it models `_vsnprintf` as `snprintf` because its hooks
match names by substring, and so "decodes" every format string passed to an
`snprintf` wrapper.)

The 163 novel strings that only Python FLOSS reports (against the defaults) are:

  - 85 pieces of strings that floss-rs reports whole: FLOSS extracts strings from
    changed bytes, so a decoded `cmd.exe /c net stop MSSQL$SYSTEM_BGC /y` also
    comes out as `e /c net stop MSSQL$SYSTEM_BGC /y` and `cmd.exe /c net sto`;
  - 23 emulator artifacts: `ineIntel` and `ntelineI` (vivisect's emulated `CPUID`),
    the fill byte as text (`fefefefe`), pieces of the emulated module path;
  - 14 static strings with junk in front (`KA\nss3.dll`, `@\Google\Chrome\User Data\Default\Login Data`);
  - 41 others, all junk on inspection: short random runs (`_o1VAo1`, `TUTUTUTU`),
    and numbers formatted from uninitialized values (`Unknown error (1096175631)`).

With `--time-budget 0`, the only plausibly real string of these is a fragment
of an API name, `teToolhelp32Snapshot`; with the default budget, floss-rs finds
it (whole) too.

The strings only floss-rs finds include `net stop` service lists in full
(27 commands), antivirus driver names (`avipbb.sys`, `cmdhlp.sys`), Task
Scheduler and registry configuration keys, and key material. They also
include noise, like intermediate states of decoders (`w1X1_1\1V1C1`) and
crypto tables built at run time. Most of the extra strings, and most of the
noise, come from emulating more candidates.

## How long to emulate decoding routines

FLOSS emulates the 20 highest-scoring candidate decoding routines (plus tight
functions). That's a limit set by Python's speed, and the question is what
limit floss-rs should use instead, without asking the user to choose.

**Method.** Every candidate of every native capa file was emulated (60s cap,
which every file finished within), recording each routine's time and strings
(`analysis.decoding_routines` in the JSON output). Routines are emulated
independently, so any stopping rule can be replayed offline from this one run:
its value is the union of the strings from the routines it would run, its cost
the sum of their times. Strings are scored two ways: *novel* (not in the file
as-is, and not mostly static text, which drops format strings filled in with
garbage), and *meaningful* (novel, at least 6 characters, mostly letters, not
repetitive). The measure is the share of each file's strings found, averaged
over files, so no one file dominates. Rules were tuned on half of the files and
checked on the other half (`scripts/budget/`).

**Along the way, two fixes.** Most of the time went to a few routines: the
slowest 1% took 59% of the decoding time, at up to 36s for one routine, and
almost never found anything. One cause was diffing memory: with a view before
every unmodeled API call, a routine that had written megabytes compared them
all at each of thousands of calls. The other was the API models' `memcpy` and
`memset` with garbage sizes, copying megabytes of fill bytes into the void, 16
bytes at a time. With both fixed (same strings), emulating every candidate of
every file takes 622s of decoding, where before it took 1,154s and four files
still hadn't finished at 60s each; the slowest routine takes 5s.

**The curve.** Share of each file's strings found, by decoding budget:

| budget | 1 thread: meaningful | novel | mean time per file | 4 threads: meaningful | novel | mean time |
|---|---|---|---|---|---|---|
| 0 (FLOSS's 20) | 41% | 40% | 1.4s | 41% | 40% | 1.4s |
| 0.5s | 67% | 68% | 1.6s | 67% | 68% | 1.7s |
| 1s | 78% | 80% | 1.8s | 88% | 89% | 1.8s |
| 2s | 87% | 88% | 2.1s | 95% | 96% | 2.0s |
| 5s | 94% | 95% | 2.6s | 99% | 99% | 2.1s |
| 10s | 99% | 99% | 3.0s | 100% | 99.5% | 2.1s |
| 20s | 99.9% | 99.4% | 3.3s | 100% | 100% | 2.1s |

(4 threads simulated from the 1-thread costs; real runs below.) The median
file takes 1.35s at any budget: the budget only matters for larger files.
With 1 thread and a 5s budget, files of under 1,000 candidates get 98.5-100%,
and files of more than 1,000 get 80%; these need 10-20s.

**Where the strings come from.** Not mostly the top 20: they give 14% of the
meaningful strings, ranks 21-50 give 40%, and ranks beyond 200 still give 22%.
On FLOSS's score, candidates are ranked only a little better than random (at
a 2s budget: 87% vs 79%), but an ideal order would find every string in 0.5s
per file: the routines that decode strings are few and cheap, and hard to spot.
(This led to a better ranking; see "Ranking candidates" below. The numbers in
this section are for FLOSS's ranking.)

**Signals that might tell when to stop, or what to emulate first:**

| signal | finding |
|---|---|
| dry spells: no new string for a while | after 1s without a new string, 23% of files still find more; after 2s, 31%. A dry spell doesn't mean a file is done, so "stop when nothing new turns up" lands on the same curve as a fixed budget (2s dry: 97% at 2.9s mean, vs a 7.5s budget: 96% at 2.8s) |
| score cliffs: the biggest drop in scores | below it, 0.10 strings per 100 routines, vs 0.83 above. Real, but the budget rarely gets there anyway |
| relative or absolute score floors | worse than budgets at every cost |
| did the top 20 find strings? | if so, 56% of files find more later; if not, 19%, but those files hold 44% of the later strings. "2s, or 20s if the top found strings" gets 99.0% at 3.2s mean, vs a 10s budget's 98.7% at 3.0s |
| budgets that scale with the file (per candidate, or proportional to the rest of the analysis) | on the same curve |
| a learned ranking from FLOSS's features (logistic regression, gradient boosting) | orders candidates little better than the score at small budgets (but see "Ranking candidates": with other features, a simpler score does better) |

None of the signals beats spending the time, so the budget stays a plain time
limit, and the improvement is in how much work fits in it: candidates are
independent, so floss-rs emulates them on several threads.

**Real runs** on the capa corpus, scored against emulating every candidate:

| | meaningful | novel | mean | p95 | max |
|---|---|---|---|---|---|
| `--time-budget 0` (FLOSS's candidates) | 41% | 40% | 1.2s | 3.5s | 10.1s |
| 1 thread, 2s budget (the old default) | 87.1% | 88.6% | 2.0s | 5.8s | 9.3s |
| 4 threads, 2s budget | 91.6% | 92.5% | 1.9s | 5.3s | 10.9s |
| **4 threads, 5s budget (the default)** | **99.5%** | **99.0%** | 2.0s | 7.5s | 10.3s |

So the default is a 5s budget, on as many threads as there are CPUs (helpers
start only once decoding has taken 0.3s, so small files don't pay for them).
With the same candidates, the results don't depend on the number of threads;
`--time-budget 0` reproduces FLOSS's fixed set. When the budget stops
decoding early, floss-rs says so, and how to emulate more.

Across the corpus, the default finds 2.4 times the novel strings of FLOSS's
fixed set (4,164 → 9,920), and twice the meaningful ones (2,537 → 5,114):
for example ransom note text, a Monero wallet registry key, a Bitcoin
`wallet.dat` path, the `root\SecurityCenter2` WMI namespace, and DNS-over-HTTPS
queries. 45% of the added strings are meaningful; the rest are noise like
format strings filled in with garbage (`Runtime error 254 at 00452E57`).

## Ranking candidates

Which candidates come first decides what FLOSS finds with its top 20, and what
floss-rs finds when the time budget runs out. FLOSS ranks candidates by a score
that predicts poorly which ones decode strings: with the top 20, it finds 39% of
the strings that emulating every candidate finds.

**The score.** FLOSS's score is the weighted average of its features' scores:
block and instruction counts, arguments, callers, loops and tight loops, and one
feature for each non-zeroing `xor`, shift, and `mov` to memory through a register.
floss-rs computes it as FLOSS's code does (recomputing it from the features
gives the same ranking); against Python FLOSS on the same files, half of the
scores agree within 0.01 and the rest differ because vivisect and lancelot find
slightly different blocks, instructions, and callers.

**What decodes strings.** The routines that find the most strings are of a few kinds:

  - functions that coordinate: big, with many calls, often called by nothing
    (entry points, thread routines). Emulating one runs the decoders it calls,
    once per string. FLOSS ranks these low (161st, of 203, for one that finds 11
    of its file's 12 strings);
  - small decoders called from many places, often with buffers on the caller's
    stack; and families that decode each string with its own small function
    (Conti: one 26-43 instruction function, with a loop over bytes, per string);
  - while FLOSS's top-ranked functions are often unrolled hashing or crypto,
    with hundreds of `xor`s, and find nothing: the average over every `xor`
    and `mov` puts them first.

The right 20 candidates would find 99% of each file's meaningful strings, and
most of them (1,342 of 2,144) are found by only one routine: the task is to spot those.

**The study.** `examples/candidate_features` computes FLOSS's features and others
for every candidate: what the callers pass (pointers to data, text, zeros, or the
stack; small constants), whether an API is called with the result, calls out
(to APIs, to functions with loops, to one function repeatedly), what the
function reaches through its calls, and what its loops do (byte accesses, xors
with constants, arithmetic, writes through pointers). Joined with what each
routine found in the all-candidates run, `scripts/budget/` measures how well
each ranks the candidates of a file (the AUC within each file, averaged), and
what each score finds with the top 20 and within time budgets. For this, strings
are also checked for reading like text (*text-like*: a character trigram model
of the corpus's static strings, which rejects junk like `fUAMwBEIszZgD` that the
*meaningful* filter lets through).

| feature (for meaningful strings) | AUC within files |
|---|---|
| instructions | 0.71 |
| byte accesses to memory | 0.69 |
| instructions in loops | 0.66 |
| calls to functions with loops | 0.66 |
| calls out | 0.65 |
| byte accesses in loops | 0.65 |
| FLOSS's score | 0.63 |
| what the callers pass, what's done with the result | 0.50-0.56 |

The call-site features, which seemed the most promising, predict almost nothing.
Size predicts best: emulating a function runs the code it calls, so bigger
functions find more. Changing FLOSS's formula to count each kind of feature once,
rather than once per instruction, makes it worse: the per-instruction counts
were working as a measure of size.

**Scores, on all native capa files** (share of each file's text-like strings found):

| score | top 20 | top 50 | 0.25s | 0.5s | 1s | 2s |
|---|---|---|---|---|---|---|
| FLOSS's score | 38.7% | 60.5% | 56.4% | 67.2% | 79.2% | 83.6% |
| instructions | 50.0% | 63.4% | 64.4% | 74.4% | 86.1% | 89.6% |
| **log(1 + instructions) + log(1 + byte accesses in loops)** | **51.8%** | 62.8% | 63.1% | 76.3% | 84.5% | 91.5% |
| logistic regression, all features (cross-validated) | 47.5% | 65.7% | 61.0% | 77.5% | 85.6% | 88.1% |
| gradient boosting, all features (cross-validated) | 57.3% | 70.3% | 63.3% | 74.0% | 85.9% | 88.3% |
| gradient boosting, FLOSS's features (cross-validated) | 51.9% | 63.3% | 64.8% | 75.3% | 80.9% | 88.7% |

A model of all the features does best with the top 20, but no better within a
time budget, and it's 200 trees over about 40 features; a linear score fitted to half
of the files does better on that half and worse on the other. The two-feature
score gets most of the gain, wasn't fitted to the data, and is easy to compute
anywhere. It beats FLOSS's score on both halves of the files, for text-like,
meaningful, and novel strings, by 3-16 points with the top 20, with top 20s that
take no longer to emulate.

**Real runs** of floss-rs with each ranking, scored against emulating every candidate
(text-like / meaningful / novel strings):

| | FLOSS's ranking | the new ranking | mean time |
|---|---|---|---|
| `--time-budget 0` (the top 20) | 38.7% / 41.1% / 39.6% | **51.8% / 47.4% / 43.1%** | 1.2s, both |
| 1 thread, 1s budget | 79.4% / 81.2% / 82.5% | **87.9% / 87.2% / 86.8%** | 1.6s, both |
| 4 threads, 5s (the default) | 99.5% / 99.5% / 99.0% | **100% / 99.8% / 99.3%** | 2.0s / 2.1s |

floss-rs now ranks candidates this way, and reports FLOSS's score too (`floss_score`).

**For Python FLOSS.** `scripts/budget/floss-size-score.patch` makes the same change
to FLOSS (`identify.py` and `features/extract.py`): it ranks by the new score,
and keeps the old one as `weighted_score`. In FLOSS, functions that nothing calls
have no call contexts and are never emulated, so replaying FLOSS's setting means
crediting them with nothing; there, ranking by the new score (among called
functions) finds 53% of the text-like strings with the top 20, where FLOSS's
score finds 38%.
Python FLOSS with the patch, on the 40-file subset (decoded strings only; the
rest of FLOSS is unchanged):

| | novel | meaningful | text-like | text-like strings of the all-candidates run found, per file |
|---|---|---|---|---|
| FLOSS | 452 | 300 | 272 | 11.2% |
| FLOSS with the patch | 446 | 313 | 288 | 21.0% |

In 35 of the 40 files the text-like strings are the same; 4 files gain and 1
loses. The 3 strings only FLOSS's score finds are junk (`Jmountain`,
`Jmounta#$`, `mountain`); the 19 only the new score finds include `Iphlpapi.dll`,
`Rstrtmgr.dll`, `RmShutdown`, API names, a list of language names, and a Conti
`net stop` command. The gain is real but small on this subset, where most files'
decoding routines are either in both top 20s or in neither.

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
  - **Noise in decoded strings**: emulating more candidates finds more format
    strings filled in with garbage, and partial decoder states. Strings that are
    mostly static text from the file could be filtered or ranked lower (the
    evaluation scripts already detect them).
  - **A keep-going mode**: emulate candidates until the user presses enter, for
    the largest files, where 5s on 4 threads covers only 4-15% of the candidates.
