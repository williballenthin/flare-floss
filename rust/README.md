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
[DESIGN.md](doc/DESIGN.md#one-file)). It uses IDA when IDA is there, and runs
without it.

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

The build needs no IDA installation: it links to the stub libraries of the
IDA SDK, which come with idalib. The binary starts on a machine without IDA,
and looks for IDA's libraries when it runs. It looks in `$IDADIR` when that's
set, and nowhere else then. Otherwise it looks in the default installation
that `hcli ida set-default` records in `ida-config.json`, in the directory
where IDA's installer puts IDA, and then where the system looks
(`LD_LIBRARY_PATH`, `PATH`, `DYLD_LIBRARY_PATH`). On macOS, the dynamic
linker has to find the libraries when the program starts. So when floss-rs
finds IDA there, it starts itself again with IDA's directory in
`DYLD_FALLBACK_LIBRARY_PATH`.

Each backend is a cargo feature, and both are on by default. To leave the IDA
backend out:

```
cargo build --release --no-default-features --features lancelot
```

On Linux, the build with both backends needs glibc, because it loads IDA's
libraries. For a binary that runs on any Linux, link the lancelot build
statically with musl (zydis needs `musl-gcc`: Debian's `musl-tools`):

```
rustup target add x86_64-unknown-linux-musl
cargo build --profile dist --target x86_64-unknown-linux-musl --no-default-features --features lancelot
./target/x86_64-unknown-linux-musl/dist/floss-rs sample.exe
```

That's a 28MB file, about 10% slower than the glibc build.

On Windows, link the C runtime statically, and then the binary runs on a
machine without the Visual C++ runtime:

```
set RUSTFLAGS=-C target-feature=+crt-static
cargo build --profile dist
```

### In IDA

`ida-plugin/` is floss-rs as a plugin for IDA Pro 9.5, a native library written
in Rust. When IDA finishes the analysis of a file, the plugin extracts the
stack strings, tight strings, and decoded strings, and stores them in the
database as synthetic strings of the provider "FLOSS". IDA shows a synthetic
string in the Strings window, and as a comment in the listing:

```
.text:0000000140001079   lea     rcx, OutputString  ; lpOutputString
.text:0000000140001079                              ; "C:\\malware.exe"
.text:0000000140001080   call    cs:OutputDebugStringA ; kernel32
.text:0000000140001080                              ; "C:\\malware.exe"
```

Each string has one address, where the Strings window goes, and the comment is
at its uses: the instructions that read the string, and the calls that take a
pointer to it.

| the string | its address | its uses |
|---|---|---|
| in global memory that holds this text only | the memory | the instructions that refer to the memory, read it, or pass it to a call |
| built by the function that uses it: a stack string, a tight string, a buffer that's decoded in place | the first instruction of the function that wrote it | the instructions that read it or pass it to a call |
| returned by a decoding routine, on the heap, the caller's stack, or a buffer that holds other texts too | the call to the routine | the call |

A function has each text once, and a string that a routine builds and consumes
itself is at the routine, rather than at each call to it. A string without
uses has its comment at its address. In global memory that comment is
repeatable, so IDA shows it wherever the address is referred to.

A decoded string that the program also has as a static string isn't stored.
Most of these are copies: a routine that copies or formats plain strings
"decodes" each of them, and in a large program they outnumber the obfuscated
strings many times. The cost is a decoded string that happens to be in the
file too, like the name of a DLL that the import table also has. Stack
strings and tight strings are stored whatever their text.

IDA saves the strings with the database, so the plugin runs once for a
database. Edit > Plugins > FLOSS extracts the strings again, and replaces
them. The output window has a summary:

```
FLOSS: extracting obfuscated strings
FLOSS: 1 stack strings, 0 tight strings, and 1 decoded strings, as 1 synthetic strings in the Strings window, in 0.07s
FLOSS: 1 of the decoded strings are static strings of the program too, and aren't among them
```

```
ida-plugin/package.sh macos-aarch64 dist/floss    # needs jq
hcli plugin install dist/floss
```

`package.sh` builds the plugin and makes the directory that IDA's Plugin
Manager installs: the library, and `ida-plugin.json`, which describes the
plugin. Its first argument is the platform of the build: `linux-x86_64`,
`linux-aarch64`, `macos-aarch64`, `macos-x86_64` or `windows-x86_64`.
[HCLI](https://hcli.docs.hex-rays.com) copies the directory to the `plugins`
directory of the IDA user directory, `~/.idapro` or `%APPDATA%\Hex-Rays\IDA Pro`.
Like floss-rs, the plugin builds without IDA.

Without the Plugin Manager, build the library with `cargo build --release` in
`ida-plugin/`, and copy it from `target/release/` to the `plugins` directory.
It's `libfloss_ida.dylib` on macOS, `libfloss_ida.so` on Linux, and
`floss_ida.dll` on Windows.

The plugin reads the program from the database, like the IDA backend, so it
works from the functions and names that the user has there. It runs with the
default options, and IDA waits until it finishes. It doesn't extract static
strings, which IDA's Strings window has. The database is x86 or x64.

IDA keeps about 1KB of synthetic strings for one address. Where a call
decodes more than that, the plugin stores the strings that fit, and reports
the number of the others in the output window. The uses come from the paths
that floss-rs emulates, so a use that only other paths reach is missing.

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
The plugin's tests start `idat`, the text-mode IDA, on a test program, with the
plugin among IDA's plugins, and read the synthetic strings of the database and
the listing at their uses from IDA's log. They need IDAPython, and the IDA
that the plugin build found, in `$IDADIR` or else in IDA's default directory.

`.github/workflows/rust.yml` is the continuous integration, on Linux, macOS
and Windows. Its build job has no IDA. It runs the tests of the lancelot
backend, and builds floss-rs, the plugin and the page for the browser. Each
run has the binaries as artifacts, for each platform. `floss-rs-<platform>`
has `floss-rs`, one binary with both backends: it runs on a machine without
IDA, and uses IDA where it finds IDA. The Linux builds run in a container
with glibc 2.28, so the Linux binary and plugin need glibc 2.28 or later,
as IDA's libraries do. `floss-ida-plugin-<platform>.zip`
is the plugin as an archive for the Plugin Manager, which
`hcli plugin install` takes, and which `hcli plugin lint` has checked. The
tests with IDA run when the repository has the secrets `HCLI_API_KEY` and
`IDA_LICENSE_ID`, with which HCLI installs IDA.
