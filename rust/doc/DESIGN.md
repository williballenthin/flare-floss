# floss-rs: design

floss-rs finds the strings that malware hides: strings built on the stack,
strings decoded by tight loops, and strings produced by decoding routines.
Like FLOSS, it does this by emulating the program's code and looking at
what the code writes to memory.

This document describes how floss-rs is put together, and why.
See [EVALUATION.md](EVALUATION.md) for how well it works.

## Overview

```
                        ┌──────────────────────────────────────────────┐
  sample.exe ──────────▶│ backend (IDA Pro, or lancelot)               │
                        │   loading, segments, functions, blocks,      │
                        │   thunks, imports, library functions         │
                        └──────────────┬───────────────────────────────┘
                                       │ Program (plain data)
                        ┌──────────────┴───────────────────────────────┐
                        │ workspace                                    │
                        │   instruction owners, callers, `ret N`       │
                        └──────────────┬───────────────────────────────┘
                                       │
              ┌────────────────────────┼─────────────────────────┐
              ▼                        ▼                         ▼
   ┌─────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
   │ features            │  │ emu (icicle)         │  │ strings              │
   │  which functions    │  │  forgiving address   │  │  find ASCII/UTF-16,  │
   │  look like decoders │  │  space, API models,  │  │  filter junk         │
   └─────────┬───────────┘  │  snapshots, diffs    │  └──────────┬───────────┘
             │              └──────────┬───────────┘             │
             │              ┌──────────┴───────────┐             │
             │              │ driver               │             │
             │              │  explore all paths / │             │
             │              │  run to an address   │             │
             │              └──────────┬───────────┘             │
             ▼                         ▼                         ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │ the analyses: stackstrings, tightstrings, decoded                    │
   └──────────────────────────────────────────────────────────────────────┘
```

Each layer only knows about the layers below it. The analyses are short:
each is a strategy (from `driver`), an observer that decides when to look at
memory, and a rule for which strings to report.

| module | lines | role |
|---|---|---|
| `program.rs` | ~100 | the program, as a backend provides it: plain data |
| `backend/ida/` | ~420 | the IDA backend: read the program from a database (`mod.rs`), which it makes from a file with idalib, or opens (`library.rs`) |
| `backend/lancelot/` | ~270 | the lancelot backend: PE files and shellcode, and FLIRT signatures (FLOSS's, built in, or files) |
| `workspace.rs` | ~250 | the program, indexed for the analyses |
| `dis.rs` | ~60 | instruction decoding (zydis) |
| `emu/mod.rs` | ~850 | the emulator: address space, execution of one instruction, calls |
| `emu/insn.rs` | ~100 | instruction classification: control flow, `rep`, `mov` to memory |
| `emu/api.rs` | ~420 | API models (malloc, memcpy, GetProcAddress, ...) and calling conventions |
| `emu/snapshot.rs` | ~260 | snapshots of emulator state, and memory diffs |
| `emu/sleigh.rs` | ~190 | the embedded SLEIGH specs, and icicle VMs built from them |
| `driver.rs` | ~230 | strategies: explore every path, explore to an address, run to an address |
| `strings.rs` | ~310 | finding strings in bytes, FLOSS's junk filters |
| `features.rs` | ~500 | scoring functions as candidate decoding routines |
| `stackstrings.rs` | ~200 | stack strings (and strings built in global memory) |
| `tightstrings.rs` | ~90 | tight strings |
| `decoded.rs` | ~200 | decoded strings |

## Program analysis: a backend, then the workspace

A backend loads the file, finds its functions, and builds their control flow
graphs. It gives floss-rs a `Program`, which is plain data:

  - the architecture (x86 or x64) and the base address,
  - the segments, with their bytes as loaded (bytes that the file doesn't initialize are zero),
  - the functions, as basic blocks with their instruction addresses and successors,
  - which functions are thunks, which are library code, and the names that are known,
  - the import address table: for each entry, the DLL and the name or ordinal.

Nothing else in floss-rs calls IDA or lancelot, so the emulator and the analyses
are the same for each backend, and the cost of a new backend is one function
that fills in a `Program`. The other end is data too: `floss::analyze(program, options)`
returns a `ResultDocument` and does no input or output. The command line and the
web page are callers that load a program, call it, and render the results.

`Workspace` indexes the program for the analyses:

  - functions as sets of basic blocks, with successors (for tight loop detection),
  - the function that each instruction belongs to,
  - the callers of each function (for finding decoding routine arguments),
    counting calls to a thunk as calls to its target,
  - for x86, each function's `ret N`, which tells the emulator how many bytes of
    arguments a callee pops when the emulator skips a call.

floss-rs decodes instructions itself, with zydis (`dis.rs`), from the bytes of
the program or of the emulator's memory. A backend says where instructions
are and leaves their meaning to floss-rs, so one decoder serves every backend,
and also code that the program writes while it runs. zydis is a C library,
linked statically. lancelot uses the same version, so a binary has one copy.

### IDA

The IDA backend links to IDA through idalib, and uses IDA's loaders,
auto-analysis, and signatures. `backend::ida::validate_available` tells
whether IDA can be used: its libraries are loaded, it starts, and it has a
license. The command line asks that once, before it picks a backend. From the database it reads the segments, each
function's flow chart, the thunk and library flags, the names that IDA or the
user gave (not the `sub_` placeholders), and the import modules.

By default the database is in a temporary directory, so floss-rs writes
nothing next to the sample. With `--idb`, the database is at that path. It's
opened if it exists, and otherwise created and kept, so the second run skips
the analysis, and the user can open the same database in IDA. An existing
database is opened as it is. floss-rs doesn't analyze it again and doesn't
save it, so floss-rs sees the user's work in it and leaves it untouched.

IDA loads a file without a format as data at address zero. For shellcode, the
backend moves that data to the base address that the lancelot backend uses,
sets the bitness, and marks the first byte as the start of a function. A file
with a format that is given as shellcode is an error, and so is a file
without a format that isn't given as shellcode.

IDA works on the thread that started it, with one database open. The backend
reads the whole program, closes the database, and returns. Emulation then
runs on many threads without IDA.

floss-rs wants the contents of the file, so the backend leaves out the
debugger segments of a database. Hex-Rays' Malware Analysis Add-On unpacks a
program when IDA opens it, by running it in a debugger. The database then has
the memory of that process, where decoding has already happened or the data
is gone. The backend warns when a debugger is active. It leaves IDA's
configuration alone: the user turns the unpacker off, with
`IDA_MALWARE_DISABLE_UNPACKER=1` in the environment.

Code that runs inside IDA, with a database open, gets the same `Program` from
`backend::ida::get_program`. That function is the cargo feature
`ida-database`. The feature `ida` adds the rest of the backend, which starts
IDA as a library and opens databases (`backend/ida/library.rs`). The
[IDA plugin](#in-ida) builds with `ida-database` alone.

### lancelot

lancelot is a Rust library, built in. It loads the PE file, finds functions
(entry points, exports, call targets, pointers that look like code),
disassembles them, and builds the control flow graph. Library functions are
named when FLIRT signatures are given. Raw shellcode becomes a single RWX
section at a fixed base address, with functions discovered from the first byte.

When a backend can't load a file, such as a .NET assembly, floss-rs warns and
reports the static strings only.

## The emulator: icicle in a forgiving address space

icicle provides the CPU: it decodes instructions with Ghidra's SLEIGH
specifications, lifts them to p-code, and interprets the p-code. floss-rs
uses icicle as an instruction-semantics engine: it executes one instruction
at a time (`Emulator::execute`), and keeps everything else, memory layout,
calls, APIs, snapshots, under its own control.

The SLEIGH specifications are open_sleigh's (a git submodule in `deps/`,
see EVALUATION.md for why), embedded into the binary. icicle compiles
specifications from a directory (`icicle_vm::build_with_path`); floss-rs
compiles the embedded ones from memory with icicle's SLEIGH compiler, and
sets up the VM the same way (`emu/sleigh.rs`), which `tests/sleigh.rs` checks
against icicle's own. That takes ~0.3s, for each emulator.

FLOSS emulates code out of context: from the start of some function, with
no process around it, and arguments that are garbage. So the address space is
built to keep code running rather than to be faithful:

  - **the image**: each segment is mapped read/write, and executable if it is in the program.
  - **the stack**: 512KB filled with `0xFE`, with the stack pointer in the middle,
    so code can read its "arguments".
  - **the heap**: a bump allocator for the API models.
  - **the void**: every other address. Reads return `0xFE`, writes are discarded.
    This is an icicle I/O memory region, so wild pointers (uninitialized
    registers, garbage arguments) never stop emulation and never allocate memory.
    This is how vivisect behaves under FLOSS, too.

### Imports and API calls

Each import address table entry points to a **stub**: an address in the void
that stands for the API. A stub decodes as a pseudo-instruction (`Flow::Api`);
executing it runs the API's model (if there is one), pops the return address
and (for x86 stdcall) the arguments, and sets the return value. Because the
stub is an ordinary address, it doesn't matter how the program gets there:
`call [IAT]`, a thunk (`jmp [IAT]`), a pointer from `GetProcAddress`, or a
pushed return address. And observers see API calls as instructions, so they can
snapshot memory right before an API runs.

The models are FLOSS's `api_hooks.py`: memory allocation, `memcpy`/`memset`/
`strlen` and friends, `sprintf`, `GetModuleFileName`, `ExitProcess`, plus
vivisect's `LoadLibrary`/`GetModuleHandle`/`GetProcAddress`, which turn
dynamically resolved APIs into stubs. Models match normalized names exactly
(`kernel32.HeapAlloc`, `_malloc`, `_HeapAlloc@12` → `heapalloc`, `malloc`, `heapalloc`),
rather than by substring as FLOSS does (where `free` matches `FreeLibrary`, and
`snprintf` matches `_vsnprintf`).

On x86, most APIs are stdcall: the API pops its arguments, so returning from a
stub has to pop them, too. How many bytes that is comes from Microsoft's
win32metadata (as JSON, from [win32json](https://github.com/marlersoft/win32json)),
and for the native API (`Nt*`, `Rtl*`, ...) from the
[phnt](https://github.com/winsiderss/phnt) headers. Both are git submodules in
`deps/`, which `build.rs` reads into a table (`build_apis.rs`), with a few
corrections (`data/apis-x86-overrides.tsv`): win32metadata records no calling
convention, so its variadic and cdecl functions are listed there, as are
exports neither source declares, like `InterlockedIncrement`. An API imported
from another DLL than the one that declares it, like an API set, is found by
name. Unknown APIs pop nothing, like in vivisect.

FLOSS uses vivisect's API database instead (as did floss-rs, at first). For the
APIs that the x86 programs in capa-testfiles import, the two disagree on 10%
(2,429 of 24,008, counting each program's imports): vivisect doesn't know 1,851
of them, like `oleaut32`, `shlwapi`, `crypt32` and `winhttp`; for 515 it has the
wrong number of arguments, like one too few for the socket functions (`recv`,
`setsockopt`, `connect`, ...) and none for `FreeSid` or `ExitThread`; and it
knows 63 that the new table doesn't, mostly undocumented `advapi32` functions,
and C runtime functions it takes for stdcall (`qsort`). A wrong count misaligns
the stack after the call, but most functions restore it from the frame pointer,
so this changed few strings: 7 of 212 x86 programs at `--time-budget 0`, and only
fragments.

### Calls

`execute` handles a call instruction in one of four ways (`CallKind`):

  - to a stub: the emulator is now at the stub, which runs next (`Api`);
  - to a library function with a model, like a statically linked `memcpy` named by FLIRT (`Library`);
  - with `CallPolicy::StepOver`, or to non-executable memory: pretend the
    callee returned 0, popping its arguments per its `ret N` (`SteppedOver`);
  - otherwise, enter the callee (`Entered`).

Thunks (`jmp [__imp_malloc]`) are followed to their target first.

### Snapshots and memory diffs

FLOSS's algorithms are built on saving and restoring emulator state, and on
comparing memory before and after. In vivisect, a snapshot is a deep copy of
all memory, which is the main reason FLOSS is slow.

icicle's memory snapshots are copy-on-write: taking one is cheap (pages are
shared with the running emulator until they're written), and two snapshots can
be compared page by page, skipping pages that are still shared. floss-rs adds a
compact register snapshot (icicle's own copies a 128KB register file), and the
heap allocator's state. A `Snapshot` takes about 4µs.

`MemoryView::changes_since` finds the runs of bytes that differ between two
views, by region (stack, global, heap). With a previous view, it only reports
runs that touch pages written since, so diffing many views of one emulation
is incremental.

### Self-modifying code

icicle doesn't support self-modifying code: it refuses writes to bytes it has
lifted, and caches the disassembly at each address forever. When the emulator
hits this, it discards all lifted code and retries the instruction. This is
rare (some packers), and costs re-lifting.

## Drivers: how to run code

FLOSS uses three ways of running code, from viv-utils. `driver.rs` has the same three:

  - **`explore`** emulates every path through a function, executing each
    instruction at most once: at each conditional branch it snapshots the
    state and queues both successors (breadth-first). Calls are stepped over,
    returns end a path. This gives concrete states for every block of a
    function, without following loops. (viv-utils' `FullCoverageEmulatorDriver`.)
  - **`explore_to`** explores until reaching an address, leaving the emulator
    there. (`SinglePathEmulatorDriver`.)
  - **`run_to`** follows the one concrete path, into calls, until reaching an
    address, with budgets for instructions and for visits to any one address.
    This runs loops, like decoders. (`DebuggerEmulatorDriver`.)

An `Observer` sees each instruction before and after it executes, and can stop
the run. The analyses are mostly observers.

## The analyses

### Stack strings (`stackstrings.rs`)

For each function (without tight loops), `explore` it, and at checkpoints,
look for strings between the stack pointer and the initial stack pointer.
The checkpoints are each call instruction, and the end of each basic block
with at least five `mov`s to memory, like FLOSS. Strings the function
references statically are excluded.

At the same checkpoints, floss-rs also diffs global memory against the
function's starting state, and reports strings the function wrote there
(as decoded strings, since they have addresses). FLOSS doesn't do this.

### Tight strings (`tightstrings.rs`)

A tight loop is a loop of one or two blocks that writes memory and doesn't call
anything (`features::find_tight_loops`). For each: `explore_to` the loop, snapshot
memory, `run_to` the block after the loop, and report the strings that the loop
wrote: on the stack these are tight strings; elsewhere they're decoded strings.

### Decoded strings (`decoded.rs`)

  1. **Pick candidates** (`features.rs`): find FLOSS's features of each function,
     like tight loops, non-zeroing `xor`s, shifts, and how often it's called
     (FLOSS's `identify.py`, feature for feature), and rank the functions by size
     and by how much their loops work on bytes. That finds more strings than FLOSS's
     weighted average of the features, which is reported too (EVALUATION.md,
     "Ranking candidates"). Take the top 20, plus all small functions with tight
     loops. Then, while decoding has taken less than the time budget (5s), keep
     going down the ranking.
  2. **Find call contexts**: `explore` each function that calls the candidate,
     and snapshot the state at each call to it. If nothing calls the candidate
     (an entry point, export, or callback), emulate it from its entry instead.
  3. **Emulate**: from each context, `run_to` the return address, following calls,
     with API models, and view memory before each call to an API that isn't
     modeled (where decoded strings are often consumed) and at the end.
  4. **Diff**: for each view, find the bytes that changed since the call, and
     report the strings in memory that overlap them (`strings::strings_touching`).

That last step differs from FLOSS on purpose: FLOSS extracts strings from the
changed bytes only, so it misses UTF-16 strings decoded into zeroed buffers
(the zero high bytes didn't change), misses or fragments strings decoded in
place where some characters didn't change, and reports fragments like `hell`
and `o world`.

The cost is that a string may include neighboring bytes that the routine
didn't write, like the rest of a reused buffer. Those can differ from one call
context to the next, which would report one variant of the string per call
(`key>`, `key*-`, ...). So each string carries its changed part, from its
first changed character to its last, and a routine reports each changed part
(at an address) once. Trimming strings to their changed part instead would
be wrong: a string decoded in place can start or end with characters that
the cipher leaves alone (Conti's `... /y`), and there's no telling those from
leftovers.

And a string that grows from one view to the next, like one decoded a
character at a time with an API call after each, is reported once, as it is
at the end, rather than as each of its prefixes.

Candidates are independent, so they're emulated on several threads, each with
its own emulator, taking candidates in order from a shared queue. Helper threads
start only once decoding has taken longer than they take to set up. The results
are put back in candidate order, so the output doesn't depend on the number of
threads (for the same candidates).

## One file

The floss-rs binary is self-contained: `build.rs` embeds everything it reads
at runtime, so it needs no files and writes none.

  - the x86 SLEIGH specifications (2.3MB), from `deps/open_sleigh`;
  - FLOSS's FLIRT signatures (15MB, used with `--flirt`, for the lancelot backend), from `floss/sigs`;
  - the table of Windows API calling conventions (`build_apis.rs`), from `deps/win32json` and `deps/phnt`.

The binary has both backends, and one dynamic dependency, IDA's libraries. A
build with only the lancelot backend has none. `build.rs` links to the stub
libraries of the IDA SDK, and records the directory of the IDA installation as
a search path. On macOS the two libraries
are weak: when the dynamic linker doesn't find them, floss-rs still starts, and
the addresses of IDA's symbols are null. `backend::ida::is_loaded` asks the
linker for one of them, and nothing calls IDA when the answer is no. In both
cases IDA can be present without a license, and then floss-rs uses lancelot.

Linux and Windows have no such link, so a binary with the IDA backend doesn't
start there without IDA's libraries. An ELF file can't mark a library as
optional, and Windows delay loading doesn't cover imported data, which IDA's
interface has. The way to make IDA optional on those systems is a dynamic
library for the IDA backend. That library links to IDA and exports one C
function, which analyzes a file and returns the `Program` as serialized data.
floss-rs loads it at run time, with `dlopen` or `LoadLibrary`, and uses
lancelot when the load fails. The main binary then has no link to IDA, so it
starts on every system. `Program` is plain data, so the interface stays one
function wide. The cost is a second build product: it ships beside the binary,
or the binary embeds it and writes it to a file before the load. floss-rs
doesn't have this library.

Built for `x86_64-unknown-linux-musl` with only the lancelot backend, it's also statically linked, so it runs
on any Linux, whatever its C library. musl's allocator made it 70% slower than
the glibc build, so a static build uses mimalloc, which leaves it ~10% slower
(40 capa test files: 91s with glibc, 100s static). The `dist` profile leaves out
debug information: the static binary is 28MB, of which 15MB is the signatures.

## In a browser

`web/` builds floss-rs as WebAssembly, with the lancelot backend, for a page
that analyzes a dropped file without uploading it. The code is the same; three things differ:

  - **No JIT.** icicle's VM always creates its JIT, which generates machine
    code with cranelift and maps it executable, which WebAssembly can't do.
    floss-rs never enables the JIT, so the web build replaces icicle's
    `icicle-jit` crate with a stub with the same interface
    (`web/icicle-jit-stub`, through a Cargo `[patch]` that applies to the web
    build only), rather than changing icicle.
  - **WASI.** icicle reads the clock (`std::time::Instant`), which the
    standard library provides in WebAssembly only on WASI (`wasm32-wasip1`).
    The module imports six WASI functions (the clock, randomness, an empty
    environment, stderr, exit), which `web/floss.js` implements, and exports
    `floss_analyze`, which returns floss-rs's JSON results.
  - **One thread**, in a web worker (`web/worker.js`). Threads would need
    shared memory, which needs cross-origin isolation headers from the server.

On 10 capa test files, the results are identical to the native build's, at
about half its speed on one thread. FLOSS's FLIRT signatures are left out
(15MB): the web build doesn't reference them, so the linker drops them.

## In IDA

`ida-plugin/` builds floss-rs as a plugin for IDA: a dynamic library that IDA
loads from its plugins directory when it opens a database. It's about 100
lines on idalib's plugin support. A type implements idalib's `IDAPlugin`, and
the `#[plugin]` attribute generates the `PLUGIN` structure that IDA looks for
in the library. When the user runs the plugin, it reads the `Program` from
the open database with `backend::ida::get_program`, calls `floss::analyze`,
and prints the strings with IDA's `msg`.

The plugin is a workspace of its own, like the web build. idalib's `plugin`
feature changes idalib from a library that hosts IDA to one that IDA hosts,
and takes away what the IDA backend opens databases with. Cargo builds idalib
once for a workspace, with one set of features, so the plugin can't share a
workspace with the command line. It depends on floss-rs with the feature
`ida-database` and no other backend.

IDA calls the plugin on its main thread. That thread reads the database and
then emulates, with helper threads on larger programs, as in the command
line. IDA waits, and the user gets it back when the strings are printed.
floss-rs's log messages go to the output window. They can come from a helper
thread, which IDA's `msg` allows. A panic that unwinds out of Rust code into
IDA ends the process, so the plugin catches a panic of the analysis and
reports it as an error in the output window.

The library links to `libida` and `libidalib`, as idalib does, and finds them
next to the IDA program that loads it.

The tests (`ida-plugin/tests`) run the plugin where it runs for users. Each
starts `idat` on a copy of a test program, with an IDC script that waits for
the analysis, runs the plugin, and exits. The test then reads what the plugin
printed from IDA's log file. Cargo builds a library for a package's tests
only when the tests can link to it, so the library is also an `rlib`, which
nothing uses.

## Choices, and what they cost

  - **One instruction at a time.** icicle can run whole blocks, and has a JIT,
    but FLOSS mostly runs code once, needs to inspect every call and branch, and
    must handle `rep` and faults precisely. Stepping costs ~0.2µs per instruction;
    lifting new code costs much more (see EVALUATION.md), so the JIT and icicle's
    lift-time optimizer are disabled.
  - **The void instead of faults.** Mapping pages on demand would make wild
    writes visible as "changed memory", allocate memory for garbage pointers,
    and needs care for accesses that straddle pages. The void reproduces
    vivisect's semantics with no special cases.
  - **Stubs instead of hooks.** One mechanism handles imports, thunks, and
    dynamically resolved APIs, and makes API calls observable.
  - **Copy-on-write snapshots.** These make FLOSS's explore-every-path strategy
    cheap, and memory diffs proportional to what changed.
  - **Exact model names, sorted call sites, explicit snapshot points.** Where
    FLOSS's behavior depends on Python set ordering or substring matches,
    floss-rs makes a deterministic choice and documents it.
