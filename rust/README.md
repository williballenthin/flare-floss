# floss-rs: FLOSS in Rust, on icicle

A port of [FLOSS](https://github.com/mandiant/flare-floss), the FLARE
Obfuscated String Solver, to Rust. It uses
[lancelot](https://github.com/williballenthin/lancelot) for program analysis and
[icicle](https://github.com/icicle-emu/icicle-emu) (MIT/Apache-2.0) for x86/x64
emulation, with SLEIGH specifications (Apache-2.0) from
[open_sleigh](https://github.com/Garfield1002/open_sleigh) embedded.

Status: research prototype. It passes FLOSS's test suite, finds strings that
FLOSS misses, and is 20-100x faster. See:

  - [doc/DESIGN.md](doc/DESIGN.md): how it works, and why;
  - [doc/EVALUATION.md](doc/EVALUATION.md): correctness, speed, and what icicle can and can't do.

```
git submodule update --init rust/deps
cargo build --release
./target/release/floss-rs sample.exe
./target/release/floss-rs -j sample.exe > results.json
./target/release/floss-rs -f sc32 shellcode.bin
```

The binary is self-contained: the data it uses is built in (see
[DESIGN.md](doc/DESIGN.md#one-file)). For one that runs on any Linux,
link it statically with musl (zydis, in lancelot, needs `musl-gcc`: Debian's `musl-tools`):

```
rustup target add x86_64-unknown-linux-musl
cargo build --profile dist --target x86_64-unknown-linux-musl
./target/x86_64-unknown-linux-musl/dist/floss-rs sample.exe
```

That's a 28MB file, about 10% slower than the glibc build.

### In a browser

floss-rs also compiles to WebAssembly: `web/` is a page that analyzes a
dropped PE file in the browser, without uploading it.

```
rustup target add wasm32-wasip1    # and clang, for zydis
web/build.sh                       # builds web/floss_web.wasm (6MB)
python3 -m http.server -d web      # then open http://localhost:8000
```

It's the same code, on one thread, at about half the native speed. See
[DESIGN.md](doc/DESIGN.md#in-a-browser) for what it takes.

Useful options:

  - `--only static stack tight decoded` / `--no ...`: choose string types.
  - `--time-budget SECONDS` (default 5): after the top 20 candidate decoding
    routines, keep emulating more candidates until decoding has taken this long.
    `0` emulates exactly FLOSS's set, for reproducible output. See
    [EVALUATION.md](doc/EVALUATION.md#how-long-to-emulate-decoding-routines) for how the default was chosen.
  - `--top-functions N` (default 20): the minimum number of candidates to emulate.
  - `--flirt`: recognize library functions with FLOSS's FLIRT signatures, which are
    built in. Off by default: loading them takes ~5s.
  - `--signatures PATH`: other FLIRT signatures (`.sig`/`.pat`, or a directory of them) to use instead.
  - `--threads N` (default: the number of CPUs): threads for emulation, on larger files.
    Each takes memory for the code it lifts (about 200MB for a program of 1,400 functions).
  - `RUST_LOG=floss=debug`: see what the emulator is doing.

Supported: PE files and shellcode, x86 and x64; static, stack, tight, and decoded strings.
Not (yet): ELF, .NET (static strings only), Go/Rust-specific strings, FLOSS's tags and rendering.

## Layout

```
src/
  main.rs            command line
  lib.rs             the pipeline: analyze a file, return results
  workspace.rs       the program, via lancelot
  flirt.rs           FLIRT signatures
  emu/               the emulator: icicle in a forgiving address space
    mod.rs             address space, executing instructions, calls
    insn.rs            instruction classification
    api.rs             API models and calling conventions
    snapshot.rs        snapshots and memory diffs
    x86.rs             x86 instructions icicle leaves unimplemented
    sleigh.rs          embedded SLEIGH specifications, compiled from memory
  driver.rs          strategies: explore every path, run to an address
  strings.rs         finding strings, filtering junk
  features.rs        ranking candidate decoding routines
  stackstrings.rs    stack strings
  tightstrings.rs    tight strings
  decoded.rs         decoded strings
build_apis.rs        generates Windows API calling conventions, from deps/
data/                corrections to them
deps/                submodules: open_sleigh (SLEIGH specifications),
                     win32json (win32metadata as JSON), phnt (native API headers)
tests/               unit tests against Python FLOSS's string functions,
                     and end-to-end tests on programs in tests/programs
web/                 the browser build: WebAssembly, and a page for it
examples/            inspect (what lancelot sees), bench, difftest (vs Unicorn)
scripts/             difftest_unicorn.py; budget/: how the time budget was chosen
```

## Tests

```
cargo test --release
tests/programs/build.sh   # rebuild the test programs; needs clang, lld-link, llvm-dlltool
```
