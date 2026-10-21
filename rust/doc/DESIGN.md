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
  sample.exe ──────────▶│ workspace (lancelot)                         │
                        │   PE/shellcode loading, functions, blocks,   │
                        │   callers, imports, thunks, FLIRT (optional) │
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
| `workspace.rs` | ~450 | the program, via lancelot |
| `emu/mod.rs` | ~800 | the emulator: address space, execution of one instruction, calls |
| `emu/insn.rs` | ~140 | instruction classification (zydis): control flow, `rep`, `mov` to memory |
| `emu/api.rs` | ~420 | API models (malloc, memcpy, GetProcAddress, ...) and calling conventions |
| `emu/snapshot.rs` | ~260 | snapshots of emulator state, and memory diffs |
| `emu/sleigh.rs` | ~50 | the embedded Ghidra SLEIGH specs that icicle compiles |
| `driver.rs` | ~230 | strategies: explore every path, explore to an address, run to an address |
| `strings.rs` | ~310 | finding strings in bytes, FLOSS's junk filters |
| `features.rs` | ~500 | scoring functions as candidate decoding routines |
| `stackstrings.rs` | ~200 | stack strings (and strings built in global memory) |
| `tightstrings.rs` | ~90 | tight strings |
| `decoded.rs` | ~200 | decoded strings |

## The workspace: lancelot

lancelot loads the PE file, finds functions (entry points, exports, call
targets, pointers that look like code), disassembles them, and builds the
control flow graph. `Workspace` wraps it with what FLOSS needs:

  - functions as sets of basic blocks, with successors (for tight loop detection),
  - the callers of each function (for finding decoding routine arguments),
    counting calls to a thunk as calls to its target,
  - the import address table, the thunks, and (if signatures are given) FLIRT names,
  - for x86, each function's `ret N`, which tells the emulator how many bytes of
    arguments a callee pops when the emulator skips a call.

Raw shellcode becomes a single RWX section at a fixed base address, with
functions discovered from the first byte.

## The emulator: icicle in a forgiving address space

icicle provides the CPU: it decodes instructions with Ghidra's SLEIGH
specifications, lifts them to p-code, and interprets the p-code. floss-rs
uses icicle as an instruction-semantics engine: it executes one instruction
at a time (`Emulator::execute`), and keeps everything else, memory layout,
calls, APIs, snapshots, under its own control.

FLOSS emulates code out of context: from the start of some function, with
no process around it, and arguments that are garbage. So the address space is
built to keep code running rather than to be faithful:

  - **the image**: each section is mapped read/write, and executable if it is in the PE.
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
`snprintf` matches `_vsnprintf`). Argument counts and calling conventions for
x86 stdcall APIs come from vivisect's API database (`data/apis-x86.tsv`).

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

  1. **Pick candidates** (`features.rs`): score each function by features like
     tight loops, non-zeroing `xor`s, shifts, and how often it's called;
     take the top 20, plus all small functions with tight loops. This is
     FLOSS's `identify.py`, feature for feature.
  2. **Find call contexts**: `explore` each function that calls the candidate,
     and snapshot the state at each call to it. If nothing calls the candidate
     (an entry point, export, or callback), emulate it from its entry instead.
  3. **Emulate**: from each context, `run_to` the return address, following calls,
     with API models, and view memory before each call to an API that isn't
     modeled (where decoded strings are often consumed) and at the end.
  4. **Diff**: for each view, find the bytes that changed since the call, and
     report the strings in memory that overlap them.

That last step differs from FLOSS on purpose: FLOSS extracts strings from the
changed bytes only, so it misses UTF-16 strings decoded into zeroed buffers
(the zero high bytes didn't change), misses or fragments strings decoded in
place where some characters didn't change, and reports fragments like `hell`
and `o world`.

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
