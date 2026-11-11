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
| `emu/access.rs` | ~380 | the access log: which instructions wrote and read which memory, and which calls took pointers to it, on each path |
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

### Which instructions wrote and used a string

Each string in the results has `writers`, the instructions whose bytes are
still in the string. An instruction whose bytes were all replaced isn't
among them, like the loop that copies a buffer before a second loop decodes
it in place. Each string also has its uses: `readers`, the instructions that
read the finished string, and `passed_to`, the calls that took a pointer
into it as an argument. All three are lists of instruction addresses, in
order. The IDA plugin puts the strings in the listing with them (see
[In IDA](#in-ida)).

Hooks on the image, stack, and heap append a record (instruction, kind,
start, length) to the access log in `emu/access.rs` for each write and read.
Each record points at the record before it on the same path. Because
`explore` forks the state at each branch, the records form a tree, and a
snapshot or memory view keeps only a `Mark`, the index of the newest record
on its path. Restoring a snapshot moves the tail back to its mark.
Consecutive accesses by one instruction to adjacent bytes extend one record,
so a decoding loop or `rep stosb` costs one record. An API model writes
memory as the call that reached it, so the call is a writer of a string that
`memcpy` copies.

To find the writers of a string, the log walks back from the view's mark and
subtracts each record's range from the bytes that no later record covers,
until none are left. A record that covers some of those bytes is a writer.

To find the uses, it walks back to the last write to the string, which is
where its contents are complete, and then follows every path that continues
from that record, each up to its next write to the string. So the uses
include what happens after the checkpoint where the analysis found the
string, on each path that `explore` took from there. The stack string and
tight string analyses ask for the uses when the function is explored. A
decoding routine runs to its return, so the uses of a decoded string are
those inside the routine: what the caller does with the string afterwards
isn't among them, and a consumer of that string derives it from `decoded_at`,
the call.

A call takes a string when one of its arguments points into it. The emulator
doesn't know the signature of the function, so it takes the arguments that
the caller set: the log has a record for each instruction that writes an
argument register, and at a call the emulator reads the registers and the
stack slots that were written since the call before. That tells an argument
from a value that an earlier call left behind. On x86 only stack slots count,
so a pointer in `ecx` for a `thiscall` or `fastcall` function isn't found.

A string that only one arm of a branch builds has no uses after the arms
join: `explore` visits the code after the join once, on the path that got
there first, and the other paths end.

The analyses clear the log before each function, so marks from an earlier
function are not valid. The log keeps at most 4M records. A read hook puts
icicle on its slow path for memory accesses, so reads are logged only while
an analysis collects uses (`track_uses`).

On five larger programs, with one thread, the uses add 5% to the time for
stack strings, 22% for tight strings, and 4% for decoded strings.

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
When the loop wrote a new string, `explore` the rest of the function from
there, which is what finds the uses of the string.

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

The binary has both backends. It starts on a machine without IDA, and uses
IDA's libraries (libida and libidalib) when it finds them. `build.rs` links to
the stub libraries of the IDA SDK, so the build needs no IDA installation.
`backend::ida::loader` brings the libraries into the process, and nothing
calls IDA before that succeeds. IDA can be present without a license, and then
floss-rs uses lancelot. Each system has its own way to make a library optional:

  - macOS: the two libraries are weak. When the dynamic linker doesn't find
    them, floss-rs still starts, and the addresses of IDA's symbols are null.
    The loader asks the linker for one of them. The build records the
    directory of the IDA installation as a search path.
  - Windows: the two libraries are delay-loaded DLLs. A call to a function of
    IDA goes through a thunk of the linker, which loads the DLL at the first
    call. The loader loads both DLLs from IDA's directory before that. Delay
    loading doesn't cover imported data, which IDA's interface has: `callui`,
    `batch`, and `under_debugger`. The code reads the address of such a
    variable from a pointer named `__imp_<name>`, usually an entry of the
    import table. The loader defines these three pointers, and sets them with
    `GetProcAddress`.
  - Linux: an ELF file can't mark a library as optional, so the binary doesn't
    name IDA's libraries. The loader defines each function of IDA that the
    binary calls as a jump through a slot, and fills the slots with `dlsym`
    after `dlopen`. The list of these functions is in the loader. A function
    that the list lacks is an undefined symbol when the binary links. The
    loader also defines the three variables, and the binary exports them, so
    IDA's libraries use the binary's copies, as they do for a program that
    links to them. On a machine without IDA, the `idalib` crate adds the stub
    libraries to the link of the binary. The build script writes two linker
    scripts with the names of the stub libraries and no content, in a
    directory that the linker searches first, so the linker uses those. A
    statically linked program can't load a dynamic library, so this binary
    needs glibc.

On Windows and Linux, the loader finds IDA when floss-rs runs. IDA itself
uses `$IDADIR` when that's set, and ends the process when IDA isn't there, so
then the loader looks in `$IDADIR` only. Otherwise it looks in the default
installation of `ida-config.json` in IDA's user directory, in the directory
where IDA's installer puts IDA, and then where the system searches for
libraries.

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
loads from its plugins directory when it opens a database. A type implements
idalib's `IDAPlugin`, and the `#[plugin]` attribute generates the `PLUGIN`
structure that IDA looks for in the library. The plugin reads the `Program`
from the open database with `backend::ida::get_program`, calls
`floss::analyze`, and stores the strings in the database as synthetic
strings, which IDA 9.5 shows in the Strings window and as comments in the
listing.

| | lines | |
|---|---|---|
| `lib.rs` | ~240 | the plugin: when to run, the database as `synth.rs` sees it, storing the strings |
| `synth.rs` | ~400 | where each string goes: plain data in, plain data out, with its tests |
| `sdk.rs` | ~130 | the functions of IDA's SDK that idalib doesn't have |

The plugin is a workspace of its own, like the web build. idalib's `plugin`
feature changes idalib from a library that hosts IDA to one that IDA hosts,
and takes away what the IDA backend opens databases with. Cargo builds idalib
once for a workspace, with one set of features, so the plugin can't share a
workspace with the command line. It depends on floss-rs with the feature
`ida-database` and no other backend.

### When it runs

The plugin runs by itself, once for a database. IDA loads it when the
database opens, and each time the plugin gives IDA the name of its provider,
"FLOSS", because IDA keeps a provider's strings in the database, but not its
name. For a new file, the analysis isn't complete yet, so the plugin hooks
the database events and runs at `auto_empty_finally`, which IDA sends when
the analysis queue first empties. IDA doesn't send that event for an existing
database, where the analysis is complete when the plugin loads, so there it
runs at once. After a run, the plugin makes the netnode `$ floss`, and it
doesn't run by itself in a database that has the netnode: the strings are
there already. The menu entry extracts them again and replaces them.

IDA calls the plugin on its main thread. That thread reads the database and
then emulates, with helper threads on larger programs, as in the command
line. IDA waits, and the user gets it back when the strings are stored.
floss-rs's log messages go to the output window. They can come from a helper
thread, which IDA's `msg` allows. A panic that unwinds out of Rust code into
IDA ends the process, so the plugin catches a panic of the analysis and
reports it as an error in the output window.

### Synthetic strings

A synthetic string is a text at an address, from a provider, with two lists
of addresses: its `uses` and its `parts`. IDA shows it in the Strings window
at its address. In the listing, a string without uses is a comment at its
address, and a string with uses is a comment at each use and not at its
address, unless the address is an instruction among the uses. The comment is
on a line of its own when the instruction has a comment already. A
repeatable string shows where its address is referred to, like a repeatable
comment, but only on lines without a comment of their own, and that excludes
the lines where IDA names the argument of an API call. IDA doesn't show
`parts`. Of the strings of one provider at one address, the listing shows the
first, and the address holds about 1KB of them.

`synth.rs` turns the results into such strings. It needs four things from
the database: the function that an address is in, whether an address is in
the program, the instructions with a data reference to an address, and
whether a text is a static string of the program. The
`writers` of a string become its `parts`, and its `readers` and `passed_to`
become its `uses`. Where the string goes depends on what it is:

  - **A string in global memory that holds this text only** is at that
    memory. Its uses are also the instructions that refer to the memory, less
    those that wrote it. IDA's references find the consumers on the paths
    that the emulator didn't take, and the comment is there next to IDA's
    own. Without any use, the string is repeatable.
  - **A string that a function builds itself** (a stack string, a tight
    string, a decoded string whose `decoded_at` is in its routine, a global
    buffer that holds several texts in turn) is at the first of its writers
    in the function that no other text has, then at the instruction where the
    analysis found it, then at the start of the function. Writers outside the
    function don't count: a helper that copies each string would collect all
    of them.
  - **A string that a routine returns** (`decoded_at` is a call in another
    function) is at the call, with the call as its use, so that the comment
    is there.

A function has each text once. floss-rs can report a text several times: as
a stack string and as a decoded string, or from several calls. The later
ones add their uses and parts to the first. A routine that builds a string
and consumes it itself is also reported from each call to it, with uses
inside the routine. Those aren't strings of the callers, so they go to the
string in the routine. When the routine has no such string, and no other
string has the text, the string stays at the call.

A decoded string whose text is a static string of the program isn't stored.
The static strings are those in the bytes of the segments, as the plugin
reads them from the database. They get the same clean-up as the strings that
the analyses find (`strings::extract_strings`), which removes junk characters
from short strings: a copy of the bytes `u%jdX` is the decoded string `ujdX`,
so that is the text to compare with. The texts must be equal, in either
encoding. This is for the candidates beyond the top of the ranking, which
floss-rs emulates while the time budget lasts: in a large program most of
them copy or format plain strings, and every copy is a decoded string. In
one 9.6MB program, about 56,400 of 59,000 decoded strings are such copies,
and four calls each copy 4MB to 5MB of the program's image to the heap with
one instruction. The filter can't tell a copy from a decoded string that is
also in the file, so it drops, for example, a decoded `kernel32.dll` when
the import table has that name. A copy of one part of a static string stays,
since the texts differ. Stack strings and tight strings aren't filtered:
their function builds them from immediates, so they aren't copies.

IDA takes at most about 1KB for an address, and counts the relations too. So
the plugin stores the strings of an address with fewer and fewer relations
until IDA accepts them, and then finds the longest run of the strings, from
the first, that fits. It reports how many strings it left out. That happens
at a call that decodes hundreds of strings, which is common in large
programs, where the candidates beyond the top of the ranking decode many
strings that the file also has in plain form.

### The SDK

idalib has no bindings for synthetic strings, database events, or netnodes,
so `sdk.rs` declares the few functions of `libida` that the plugin calls,
with the layouts of `qvector` and `synth_string_t` (88 bytes) from the SDK's
headers. The functions are C exports, so there's no C++ to build.

The library links to `libida` and `libidalib`, as idalib does, and finds them
next to the IDA program that loads it.

### Tests

`synth.rs` has unit tests, with a few lines of data in place of a database.
The tests in `ida-plugin/tests` run the plugin where it runs for users. Each
starts `idat` on a copy of a test program, with a user directory that has the
plugin in `plugins/floss/`, with its `ida-plugin.json`, as the Plugin Manager
installs it. So IDA loads and runs the plugin as it does for a user. An
IDAPython script waits for the analysis, prints the synthetic strings of the
database and the listing at their uses, and exits; the test reads that from
IDA's log file. One test opens the saved database again, and checks that the
strings are there and that the plugin didn't run. Cargo builds a library for
a package's tests only when the tests can link to it, so the library is also
an `rlib`, which nothing uses.

### Packaging

`ida-plugin.json` describes the plugin to IDA and to its Plugin Manager. The
entry point there is `floss_ida`, without an extension, and IDA adds the
extension of its platform. `package.sh` builds the library and makes the
directory that the Plugin Manager installs: the manifest, the README, and the
library as `floss_ida.so`, `floss_ida.dylib` or `floss_ida.dll`. An archive
is for one platform, and its manifest names that platform only. One archive
can't hold both Linux libraries, because they have the same name. The Plugin
Manager picks the archive of a release that names the platform of the user.

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
