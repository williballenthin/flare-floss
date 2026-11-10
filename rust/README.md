# floss-rs: FLOSS in Rust, on icicle

A port of [FLOSS](https://github.com/mandiant/flare-floss), the FLARE
Obfuscated String Solver, to Rust. For program analysis it uses
[IDA Pro](https://hex-rays.com/ida-pro), through
[idalib](https://github.com/idalib-rs/idalib), or
[lancelot](https://github.com/williballenthin/lancelot), which needs nothing installed.
For x86/x64 emulation it uses
[icicle](https://github.com/icicle-emu/icicle-emu) (MIT/Apache-2.0), with SLEIGH
specifications (Apache-2.0) from
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
./target/release/floss-rs --idb sample.exe.i64 sample.exe   # keep IDA's database, and use it next time
./target/release/floss-rs sample.exe.i64                    # an existing IDA database
```

The binary is self-contained: the data it uses is built in (see
[DESIGN.md](doc/DESIGN.md#one-file)). Its one dynamic dependency is IDA, which
it uses when IDA is there.

### Backends

A backend finds the program's functions and control flow. A build has two,
and floss-rs picks one when it runs:

| backend | needs | reads |
|---|---|---|
| `ida` | IDA Pro 9.5 with a license for idalib | what IDA loads, x86 and x64; shellcode; IDA databases |
| `lancelot` | nothing | PE files and shellcode |

With `--backend auto`, the default, floss-rs uses IDA when it finds IDA's
libraries and IDA has a license. Otherwise it uses lancelot, and logs why.
`--backend ida` and `--backend lancelot` name one, and floss-rs stops with an
error when it can't use that one. An IDA database as the input, or `--idb`,
needs IDA.

Both backends give the same strings on the test files. IDA finds more
functions and names library functions with its own signatures, and takes
about a second longer per file (see
[EVALUATION.md](doc/EVALUATION.md#ida-and-lancelot)).

The build needs an IDA installation, in `$IDADIR` or else in IDA's default
directory, and records that directory in the binary. When it runs, floss-rs
looks for IDA's libraries there, and then where the dynamic linker looks
(`DYLD_LIBRARY_PATH`, `LD_LIBRARY_PATH`). On macOS, floss-rs runs without
them. On Linux and Windows, a binary with the IDA backend doesn't start
without them.

Each backend is a cargo feature, and both are on by default. For a machine
without IDA, leave the IDA backend out, and then the binary has no dynamic
dependencies:

```
cargo build --release --no-default-features --features lancelot
```

For a binary that runs on any Linux, link the lancelot build statically with
musl (zydis needs `musl-gcc`: Debian's `musl-tools`):

```
rustup target add x86_64-unknown-linux-musl
cargo build --profile dist --target x86_64-unknown-linux-musl --no-default-features --features lancelot
./target/x86_64-unknown-linux-musl/dist/floss-rs sample.exe
```

That's a 28MB file, about 10% slower than the glibc build.

### In IDA

`ida-plugin/` is floss-rs as a plugin for IDA Pro 9.5, a native library written
in Rust. Edit > Plugins > FLOSS extracts the stack strings, tight strings, and
decoded strings of the open database, and prints them to the output window:

```
FLOSS: extracting obfuscated strings
FLOSS STACK STRINGS (1)
0x140001064: kernel32.dll
FLOSS TIGHT STRINGS (0)
FLOSS DECODED STRINGS (1)
0x140001000: kernel32.dll
FLOSS: finished in 0.07s
```

A double click on an address goes there. For a stack string or a tight string,
it's the instruction where floss-rs found the string. For a decoded string,
it's the call to the decoding routine.

```
cd ida-plugin
cargo build --release
cp target/release/libfloss_ida.dylib ~/.idapro/plugins/
```

The library is `libfloss_ida.so` on Linux, and `floss_ida.dll` on Windows,
where the directory is `%APPDATA%\Hex-Rays\IDA Pro\plugins`. The build finds
IDA as the floss-rs build does.

The plugin reads the program from the database, like the IDA backend, so it
works from the functions and names that the user has there. It runs with the
default options, and IDA waits until it finishes. It doesn't print static
strings, which IDA's Strings window has. The database is x86 or x64.

### In a browser

floss-rs also compiles to WebAssembly, with the lancelot backend: `web/` is a
page that analyzes a dropped PE file in the browser, without uploading it.

```
rustup target add wasm32-wasip1    # and clang, for zydis
web/build.sh                       # builds web/floss_web.wasm (6MB)
python3 -m http.server -d web      # then open http://localhost:8000
```

On macOS, build with LLVM's archiver (`AR=llvm-ar RANLIB=llvm-ranlib web/build.sh`):
Apple's `ar` leaves the WebAssembly objects of zydis out of its library.

It's the same code, on one thread, at about half the native speed. See
[DESIGN.md](doc/DESIGN.md#in-a-browser) for what it takes.

Useful options:

  - `--only static stack tight decoded` / `--no ...`: choose string types.
  - `--time-budget SECONDS` (default 5): after the top 20 candidate decoding
    routines, keep emulating more candidates until decoding has taken this long.
    `0` emulates exactly FLOSS's set, for reproducible output. See
    [EVALUATION.md](doc/EVALUATION.md#how-long-to-emulate-decoding-routines) for how the default was chosen.
  - `--top-functions N` (default 20): the minimum number of candidates to emulate.
  - `--backend auto|ida|lancelot` (default auto): the program analysis backend.
    `auto` is IDA when it's installed and has a license, and lancelot otherwise.
  - `--idb PATH`, with IDA: the database to use. It's opened when it exists, and
    otherwise created from the sample and kept. Without it, the database is
    temporary, and floss-rs writes nothing next to the sample.
  - `--flirt`, with lancelot: recognize library functions with FLOSS's FLIRT signatures,
    which are built in. Off by default: loading them takes ~5s.
  - `--signatures PATH`, with lancelot: other FLIRT signatures (`.sig`/`.pat`, or a
    directory of them) to use instead.
  - `--threads N` (default: the number of CPUs): threads for emulation, on larger files.
    Each takes memory for the code it lifts (about 200MB for a program of 1,400 functions).
  - `RUST_LOG=floss=debug`: see what the emulator is doing.

Supported: PE files, shellcode, and IDA databases of them, x86 and x64; static, stack,
tight, and decoded strings. Static strings come from the bytes of the sample: for an
IDA database, that's the file next to it with the same name less the extension
(`sample.exe` for `sample.exe.i64`), and without that file, there are none.
Not (yet): ELF, .NET (static strings only), Go/Rust-specific strings, FLOSS's tags and rendering.

## Layout

```
src/
  main.rs            command line
  lib.rs             the pipeline: analyze a file, return results
  program.rs         the program, as a backend describes it: plain data
  backend/           the backends, which make a program from a file
    ida/               IDA Pro, through idalib
    lancelot/          lancelot, and its FLIRT signatures
  workspace.rs       the program, indexed for the analyses: owners, callers, thunks
  dis.rs             instruction decoding
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
                     and end-to-end tests on programs in tests/programs, with each backend
ida-plugin/          the IDA plugin, and its tests
web/                 the browser build: WebAssembly, and a page for it
examples/            inspect (what a backend sees), bench, candidate_features, difftest (vs Unicorn)
scripts/             difftest_unicorn.py; budget/: how the time budget was chosen
```

## Tests

```
tests/programs/build.sh                    # build the test programs; needs clang, lld-link, llvm-dlltool
cargo test --release
cargo test --release --test ida -- --test-threads=1   # end to end, with IDA
cargo test --release --test lancelot                  # end to end, with lancelot
(cd ida-plugin && cargo test --release)               # the plugin, inside IDA
```

The end-to-end tests are in `tests/common`, and run once with each backend.
IDA only works on the main thread, so `tests/test_ida.rs` runs its tests there,
one at a time, with [libtest-mimic](https://github.com/LukasKalbertodt/libtest-mimic).
The plugin's tests start `idat`, the text-mode IDA, on a test program, run the
plugin there, and read the strings from IDA's log.
