# floss-rs: FLOSS in Rust, on icicle

A port of [FLOSS](https://github.com/mandiant/flare-floss), the FLARE
Obfuscated String Solver, to Rust. It uses
[lancelot](https://github.com/williballenthin/lancelot) for program analysis and
[icicle](https://github.com/icicle-emu/icicle-emu) (MIT/Apache-2.0) for x86/x64
emulation, with Ghidra's SLEIGH specifications (Apache-2.0) embedded.

Status: research prototype. It passes FLOSS's test suite, finds strings that
FLOSS misses, and is 20-100x faster. See:

  - [doc/DESIGN.md](doc/DESIGN.md): how it works, and why;
  - [doc/EVALUATION.md](doc/EVALUATION.md): correctness, speed, and what icicle can and can't do.

```
cargo build --release
./target/release/floss-rs sample.exe
./target/release/floss-rs -j sample.exe > results.json
./target/release/floss-rs -f sc32 shellcode.bin
```

Useful options:

  - `--only static stack tight decoded` / `--no ...`: choose string types.
  - `--time-budget SECONDS` (default 2): after the top 20 candidate decoding
    routines, keep emulating more candidates until decoding has taken this long.
    `0` emulates exactly FLOSS's set, for reproducible output.
  - `--top-functions N` (default 20): the minimum number of candidates to emulate.
  - `--signatures PATH`: FLIRT signatures (`.sig`/`.pat`, or a directory of them)
    to recognize library functions. Off by default: loading FLOSS's signatures takes ~5s.
  - `--threads N`: threads for stack and tight strings, on large files.
  - `RUST_LOG=floss=debug`: see what the emulator is doing.

Supported: PE files and shellcode, x86 and x64; static, stack, tight, and decoded strings.
Not (yet): ELF, .NET (static strings only), Go/Rust-specific strings, FLOSS's tags and rendering.

## Layout

```
src/
  main.rs            command line
  lib.rs             the pipeline: analyze a file, return results
  workspace.rs       the program, via lancelot
  emu/               the emulator: icicle in a forgiving address space
    mod.rs             address space, executing instructions, calls
    insn.rs            instruction classification
    api.rs             API models and calling conventions
    snapshot.rs        snapshots and memory diffs
    x86.rs             x86 instructions icicle leaves unimplemented
    sleigh.rs          embedded SLEIGH specifications
  driver.rs          strategies: explore every path, run to an address
  strings.rs         finding strings, filtering junk
  features.rs        ranking candidate decoding routines
  stackstrings.rs    stack strings
  tightstrings.rs    tight strings
  decoded.rs         decoded strings
data/apis-x86.tsv    Windows API calling conventions (from vivisect)
sleigh/x86/          Ghidra's x86 SLEIGH specifications
tests/               unit tests against Python FLOSS's string functions,
                     and end-to-end tests on programs in tests/programs
examples/            inspect (what lancelot sees), bench, difftest (vs Unicorn)
scripts/             difftest_unicorn.py
```

## Tests

```
cargo test --release
tests/programs/build.sh   # rebuild the test programs; needs clang, lld-link, llvm-dlltool
```
