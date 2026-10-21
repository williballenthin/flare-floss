//! The emulator: an icicle x86/x64 CPU inside a minimal, forgiving,
//! Windows-like user-mode address space.
//!
//! FLOSS emulates code out of context: it starts in the middle of a
//! program, with no real process around it, and only cares about what
//! the code writes to memory. So the address space here is designed to
//! keep code running rather than to be faithful:
//!
//!   - the image's sections are mapped read/write (and executable, when the section is),
//!   - there's a stack and a heap (a bump allocator used by the API models),
//!   - every other address is backed by the `Void`: reads return `FILL_BYTE`
//!     and writes are discarded; so wild reads and writes don't stop emulation.
//!   - imported functions are synthetic "stub" addresses. Execution never
//!     actually reaches them: `execute` notices when the program counter
//!     lands on a stub and handles the API call (see `api`).
//!
//! The emulator executes one instruction at a time (`execute`);
//! the strategies for exploring code live in `crate::driver`.
use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Result};
use icicle_vm::cpu::{
    mem::{perm, perm::MemResult, IoMemory, Mapping},
    ExceptionCode,
};
use icicle_vm::VmExit;
use lancelot::{analysis::dis::zydis, arch::Arch, aspace::AddressSpace, VA};

use crate::workspace::Workspace;

pub mod api;
pub mod insn;
pub mod sleigh;
pub mod snapshot;

pub use insn::{Flow, Insn};
pub use snapshot::{MemoryView, Snapshot};

/// byte used to fill memory that the program never initialized:
/// the stack, and pages that appear on demand.
/// this matches vivisect's "taint byte" as configured by FLOSS.
pub const FILL_BYTE: u8 = 0xFE;

pub const PAGE_SIZE: u64 = 0x1000;

const STACK_SIZE: u64 = 0x80000;
/// leave room above the initial stack pointer for "arguments" and caller frames.
const STACK_HEADROOM: u64 = 0x40000;
/// the largest single allocation made by the API models.
pub const MAX_ALLOCATION: u64 = 5 * 1024 * 1024;
/// spacing between import stubs.
const STUB_SIZE: u64 = 0x10;

/// Where things live in the emulated address space.
#[derive(Debug, Clone)]
pub struct Layout {
    /// page-aligned ranges of the loaded image.
    pub image: Vec<std::ops::Range<VA>>,
    pub stack: std::ops::Range<VA>,
    /// the initial stack pointer at the start of each emulation.
    pub initial_sp: VA,
    pub heap: std::ops::Range<VA>,
    /// import stubs and handles returned by LoadLibrary et al. are never mapped.
    pub stubs: std::ops::Range<VA>,
    pub modules: std::ops::Range<VA>,
}

impl Layout {
    /// choose the stack, heap, and stub regions so they don't overlap the image.
    fn new(image: Vec<std::ops::Range<VA>>) -> Result<Layout> {
        // all candidates are below 2GB, so they work for 32-bit code, too.
        // each region is 16MB, which is plenty for the stack (512KB), heap, stubs, and module handles.
        const REGION: u64 = 0x0100_0000;
        let candidates = (0x10..0x80u64).map(|i| i * REGION);
        let mut free = candidates.filter(|&start| {
            image
                .iter()
                .all(|r| r.end <= start || start + REGION <= r.start)
        });

        let mut next = || free.next().ok_or_else(|| anyhow!("no room in the address space"));
        let stack_base = next()?;
        let heap_base = next()?;
        let stub_base = next()?;
        let module_base = next()?;

        Ok(Layout {
            image,
            stack: stack_base..stack_base + STACK_SIZE,
            initial_sp: stack_base + STACK_SIZE - STACK_HEADROOM,
            heap: heap_base..heap_base + REGION,
            stubs: stub_base..stub_base + REGION,
            modules: module_base..module_base + REGION,
        })
    }

    pub fn is_stack(&self, va: VA) -> bool {
        self.stack.contains(&va)
    }

    pub fn is_image(&self, va: VA) -> bool {
        self.image.iter().any(|r| r.contains(&va))
    }
}

/// What lives at an import stub address: the API that the program
/// expects to find there.
#[derive(Debug, Clone)]
pub struct Stub {
    /// lowercase DLL name without extension, like "kernel32".
    pub dll: String,
    /// the exported name, or "#<ordinal>".
    pub name: String,
}

impl Stub {
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.dll, self.name)
    }
}

/// How `execute` treats a call to another function in the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPolicy {
    /// don't emulate the callee; pretend it returned 0.
    StepOver,
    /// emulate the callee.
    StepInto,
}

/// Options for `execute`.
#[derive(Debug, Clone, Copy)]
pub struct ExecOptions {
    pub calls: CallPolicy,
    /// use the API models (`api::Model`) for imports and recognized library functions,
    /// rather than just returning 0.
    pub api_models: bool,
    /// the most iterations of a `rep`-prefixed instruction to emulate;
    /// like vivisect's `i386:repmax` option.
    pub rep_max: u32,
}

/// A call made by an instruction, as reported by `execute`.
#[derive(Debug, Clone)]
pub struct Call {
    /// address of the call instruction (or jump, for tail calls).
    pub from: VA,
    pub target: VA,
    /// the name of the API or library function, if known.
    pub name: Option<String>,
    pub kind: CallKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// a call to an import: the emulator is now at the import stub,
    /// which handles the API when it's executed next (see `Flow::Api`).
    Api,
    /// a recognized library function, like `memcpy`, handled by an API model.
    Library,
    /// skipped: the emulator pretended the function returned 0.
    SteppedOver,
    /// the emulator is now at the first instruction of the callee.
    Entered,
}

/// The outcome of executing one instruction.
#[derive(Debug, Clone)]
pub enum Event {
    /// the instruction executed. if it was a call, here's what happened.
    Executed(Option<Call>),
    /// an API model asked to stop emulation (like ExitProcess).
    Stop,
}

/// Why `execute` couldn't execute an instruction.
#[derive(Debug, Clone)]
pub enum Fault {
    /// the program counter doesn't point to executable memory.
    NotExecutable(VA),
    /// the bytes at the program counter don't decode.
    InvalidInstruction(VA),
    /// an instruction that stops execution, like `int3` or `hlt`.
    Trap(VA),
    /// icicle couldn't emulate the instruction.
    Unsupported(VA, String),
}

/// The varnodes for the registers that FLOSS needs by name.
struct Registers {
    sp:   pcode::VarNode,
    /// return value: eax/rax.
    ret:  pcode::VarNode,
    /// integer argument registers, for x64: rcx, rdx, r8, r9.
    args: Vec<pcode::VarNode>,
    /// general purpose registers, set to zero at the start of emulation.
    gprs: Vec<pcode::VarNode>,
}

impl Registers {
    fn new(vm: &icicle_vm::Vm, arch: Arch) -> Result<Registers> {
        let get = |name: &str| -> Result<pcode::VarNode> {
            vm.cpu
                .arch
                .sleigh
                .get_reg(name)
                .and_then(|r| r.get_var())
                .ok_or_else(|| anyhow!("missing register: {name}"))
        };

        Ok(match arch {
            Arch::X32 => Registers {
                sp:   get("ESP")?,
                ret:  get("EAX")?,
                args: vec![],
                gprs: ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
                    .iter()
                    .map(|n| get(n))
                    .collect::<Result<_>>()?,
            },
            Arch::X64 => Registers {
                sp:   get("RSP")?,
                ret:  get("RAX")?,
                args: ["RCX", "RDX", "R8", "R9"].iter().map(|n| get(n)).collect::<Result<_>>()?,
                gprs: [
                    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
                    "R15",
                ]
                .iter()
                .map(|n| get(n))
                .collect::<Result<_>>()?,
            },
        })
    }
}

/// The memory behind every address that isn't part of the image, stack, or heap:
/// reads return `FILL_BYTE` and writes go nowhere, like vivisect's emulator.
/// So wild reads and writes, through pointers the emulator never initialized,
/// don't stop emulation.
struct Void;

impl IoMemory for Void {
    fn read(&mut self, _addr: u64, buf: &mut [u8]) -> MemResult<()> {
        buf.fill(FILL_BYTE);
        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }
}

/// Counters describing what the emulator did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    /// instructions executed (`rep` iterations count once each).
    pub instructions:  u64,
    pub api_calls:     u64,
    pub snapshots:     u64,
    /// times the lifted code was discarded, because of self-modifying code.
    pub code_flushes:  u64,
    pub snapshot_us:   u64,
    pub restore_us:    u64,
    /// instructions icicle couldn't emulate, by reason and mnemonic.
    pub unsupported:   BTreeMap<String, u64>,
}

pub struct Emulator {
    pub stats:       Stats,
    vm:              icicle_vm::Vm,
    pub arch:        Arch,
    regs:            Registers,
    pub layout:      Layout,
    decoder:         zydis::Decoder,
    insns:           HashMap<VA, Option<Insn>>,
    /// API stubs by address; grows when GetProcAddress resolves new APIs.
    stubs:           BTreeMap<VA, Stub>,
    /// fake module handles returned by LoadLibrary et al., to DLL name.
    modules:         BTreeMap<VA, String>,
    /// the next free address in the heap; part of the snapshotted state.
    heap_next:       VA,
    /// the state right after loading, before any emulation.
    pristine:        Option<Snapshot>,
    /// names of functions in the program (imports, exports, FLIRT matches),
    /// used to recognize library functions that have API models.
    function_names:  BTreeMap<VA, String>,
    /// for x86 functions in the program: bytes of arguments the callee pops (`ret N`).
    callee_cleanup:  BTreeMap<VA, u16>,
    /// functions that just jump to another function, like `jmp [__imp_malloc]`.
    thunks:          std::collections::BTreeSet<VA>,
}

impl Emulator {
    pub fn new(ws: &Workspace) -> Result<Emulator> {
        let arch = ws.arch();
        let triple = match arch {
            Arch::X32 => "i686-none",
            Arch::X64 => "x86_64-none",
        };
        let config = icicle_vm::cpu::Config {
            triple: triple.parse().map_err(|_| anyhow!("invalid target triple"))?,
            // the shadow stack would complain about our fake returns.
            enable_shadow_stack: false,
            // most code is emulated once, so compiling or optimizing it isn't worth it.
            enable_jit: false,
            optimize_instructions: false,
            optimize_block: false,
            ..Default::default()
        };
        let mut vm = icicle_vm::build_with_path(&config, &sleigh::processors_dir()?)
            .map_err(|e| anyhow!("failed to build icicle VM: {e}"))?;

        let regs = Registers::new(&vm, arch)?;
        let decoder = lancelot::analysis::dis::get_disassembler(ws.module())?;

        // map the image.
        let mut image: Vec<std::ops::Range<VA>> = vec![];
        for section in ws.module().sections.iter() {
            let start = section.virtual_range.start & !(PAGE_SIZE - 1);
            let end = (section.virtual_range.end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            if start >= end {
                continue;
            }
            let mut p = perm::READ | perm::WRITE | perm::INIT;
            if section.permissions.intersects(lancelot::module::Permissions::X) {
                p |= perm::EXEC;
            }
            // sections may share pages; later sections win, which is fine since we copy bytes below.
            vm.cpu.mem.map_memory_len(start, end - start, Mapping { perm: p, value: 0 });
            image.push(start..end);
        }
        for section in ws.module().sections.iter() {
            let range = &section.virtual_range;
            let buf = ws
                .module()
                .address_space
                .read_bytes(range.start, (range.end - range.start) as usize)
                .unwrap_or_default();
            if !buf.is_empty() {
                vm.cpu
                    .mem
                    .write_bytes(range.start, &buf, perm::NONE)
                    .map_err(|e| anyhow!("failed to write section {}: {e:?}", section.name))?;
            }
        }

        let layout = Layout::new(image)?;

        vm.cpu.mem.map_memory_len(layout.stack.start, STACK_SIZE, Mapping {
            perm:  perm::READ | perm::WRITE | perm::INIT,
            value: FILL_BYTE,
        });

        // everything else is the void.
        let void = vm.cpu.mem.register_io_handler(Void);
        let mut used: Vec<std::ops::Range<VA>> = layout.image.clone();
        used.push(layout.stack.clone());
        used.sort_by_key(|r| r.start);
        let top: u64 = match arch {
            Arch::X32 => 1 << 32,
            Arch::X64 => u64::MAX,
        };
        let mut cursor = 0u64;
        for r in used.iter().chain(std::iter::once(&(top..top))) {
            if r.start > cursor {
                vm.cpu.mem.map_memory_len(cursor, r.start - cursor, void);
            }
            cursor = cursor.max(r.end);
        }

        let mut emu = Emulator {
            stats: Default::default(),
            vm,
            arch,
            regs,
            heap_next: layout.heap.start,
            layout,
            decoder,
            insns: Default::default(),
            stubs: Default::default(),
            modules: Default::default(),
            pristine: None,
            function_names: ws.library_function_names(),
            callee_cleanup: ws.callee_cleanup(),
            thunks: ws.functions().map(|f| f.va).filter(|&va| ws.is_thunk(va)).collect(),
        };

        // point each import address table entry at a stub.
        for (slot, stub) in ws.imports() {
            let addr = emu.add_stub(stub);
            emu.write_ptr(slot, addr)?;
        }

        emu.pristine = Some(emu.snapshot());
        Ok(emu)
    }

    // --- state ---

    /// restore the emulator to its state right after loading,
    /// ready to run the given function.
    pub fn reset(&mut self, pc: VA) {
        let pristine = self.pristine.clone().expect("pristine state");
        self.restore(&pristine);
        for &reg in self.regs.gprs.iter() {
            self.vm.cpu.write_reg(reg, 0u64);
        }
        self.set_sp(self.layout.initial_sp);
        self.set_pc(pc);
    }

    /// restore the emulator to its state right after loading, as if the function at `pc`
    /// was just called. returns the return address, which is in the void.
    pub fn reset_for_call(&mut self, pc: VA) -> VA {
        self.reset(pc);
        let ret = self.layout.modules.end - PAGE_SIZE;
        let sp = self.sp() - self.pointer_size();
        self.set_sp(sp);
        let _ = self.write_ptr(sp, ret);
        ret
    }

    pub fn snapshot(&mut self) -> Snapshot {
        let t = std::time::Instant::now();
        self.stats.snapshots += 1;
        let s = Snapshot::capture(&mut self.vm.cpu, self.heap_next);
        self.stats.snapshot_us += t.elapsed().as_micros() as u64;
        s
    }

    pub fn restore(&mut self, snapshot: &Snapshot) {
        let t = std::time::Instant::now();
        self.heap_next = snapshot.restore_into(&mut self.vm.cpu);
        self.stats.restore_us += t.elapsed().as_micros() as u64;
    }

    pub fn pc(&self) -> VA {
        self.vm.cpu.read_pc()
    }

    pub fn set_pc(&mut self, va: VA) {
        self.vm.cpu.write_pc(va);
    }

    pub fn sp(&mut self) -> VA {
        self.vm.cpu.read_reg(self.regs.sp)
    }

    pub fn set_sp(&mut self, va: VA) {
        self.vm.cpu.write_reg(self.regs.sp, va);
    }

    pub fn set_return_value(&mut self, value: u64) {
        self.vm.cpu.write_reg(self.regs.ret, value);
    }

    pub fn pointer_size(&self) -> u64 {
        self.arch.pointer_size() as u64
    }

    pub fn heap_next(&self) -> VA {
        self.heap_next
    }

    // --- memory ---

    /// read memory; bytes that aren't mapped read as `FILL_BYTE`.
    pub fn read_mem(&mut self, va: VA, len: usize) -> Vec<u8> {
        let mut buf = vec![FILL_BYTE; len];
        let mut offset = 0usize;
        while offset < len {
            let addr = va.wrapping_add(offset as u64);
            let chunk = ((PAGE_SIZE - (addr % PAGE_SIZE)) as usize).min(len - offset);
            // a failed read leaves the fill bytes in place.
            let _ = self
                .vm
                .cpu
                .mem
                .read_bytes(addr, &mut buf[offset..offset + chunk], perm::NONE);
            offset += chunk;
        }
        buf
    }

    /// write memory; writes to the void are discarded.
    pub fn write_mem(&mut self, va: VA, buf: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset < buf.len() {
            let addr = va.wrapping_add(offset as u64);
            let chunk = ((PAGE_SIZE - (addr % PAGE_SIZE)) as usize).min(buf.len() - offset);
            self.vm
                .cpu
                .mem
                .write_bytes(addr, &buf[offset..offset + chunk], perm::NONE)
                .map_err(|e| anyhow!("write to {addr:#x}: {e:?}"))?;
            offset += chunk;
        }
        Ok(())
    }

    pub fn read_ptr(&mut self, va: VA) -> VA {
        let buf = self.read_mem(va, self.arch.pointer_size());
        match self.arch {
            Arch::X32 => u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64,
            Arch::X64 => u64::from_le_bytes(buf[..8].try_into().unwrap()),
        }
    }

    pub fn write_ptr(&mut self, va: VA, value: VA) -> Result<()> {
        match self.arch {
            Arch::X32 => self.write_mem(va, &(value as u32).to_le_bytes()),
            Arch::X64 => self.write_mem(va, &value.to_le_bytes()),
        }
    }

    /// read a NUL-terminated string of 1- or 2-byte characters, up to `max` characters.
    pub fn read_cstr(&mut self, va: VA, max: usize, wide: bool) -> Vec<u8> {
        let width = if wide { 2 } else { 1 };
        let buf = self.read_mem(va, max * width);
        buf.chunks(width)
            .take_while(|c| c.iter().any(|&b| b != 0))
            .map(|c| c[0])
            .collect()
    }

    /// allocate zeroed memory from the heap; part of the snapshotted state.
    pub fn allocate(&mut self, size: u64) -> Result<VA> {
        let size = size.clamp(1, MAX_ALLOCATION);
        // leave a little slack after each allocation, like FLOSS, and keep 16-byte alignment.
        let size = (size + 4 + 0xF) & !0xF;
        let va = self.heap_next;
        if va + size > self.layout.heap.end {
            return Err(anyhow!("heap exhausted"));
        }

        let page_start = (va + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let page_end = (va + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if page_end > page_start {
            // carve the new pages out of the void.
            // executable, like FLOSS's heap, in case a decoder writes code there.
            self.vm.cpu.mem.unmap_memory_len(page_start, page_end - page_start);
            self.vm.cpu.mem.map_memory_len(page_start, page_end - page_start, Mapping {
                perm:  perm::READ | perm::WRITE | perm::EXEC | perm::INIT,
                value: 0,
            });
        }
        self.heap_next = va + size;
        Ok(va)
    }

    /// a view of the current memory contents.
    pub fn memory(&mut self) -> MemoryView {
        MemoryView::new(self.vm.cpu.mem.snapshot(), self.layout.clone())
    }

    // --- APIs ---

    fn add_stub(&mut self, stub: Stub) -> VA {
        let addr = self.layout.stubs.start + STUB_SIZE * self.stubs.len() as u64;
        self.stubs.insert(addr, stub);
        addr
    }

    /// the stub for the given API, creating it if necessary.
    pub fn stub_for(&mut self, dll: &str, name: &str) -> VA {
        let found = self
            .stubs
            .iter()
            .find(|(_, s)| s.dll == dll && s.name == name)
            .map(|(&va, _)| va);
        found.unwrap_or_else(|| {
            self.add_stub(Stub {
                dll:  dll.to_string(),
                name: name.to_string(),
            })
        })
    }

    pub fn is_stub(&self, va: VA) -> bool {
        self.stubs.contains_key(&va)
    }

    /// is there an API model for the import at this stub?
    pub fn is_modeled_api(&self, va: VA) -> bool {
        self.stubs
            .get(&va)
            .map(|stub| api::find_model(&stub.qualified_name()).is_some())
            .unwrap_or(false)
    }

    pub fn stub_at(&self, va: VA) -> Option<&Stub> {
        self.stubs.get(&va)
    }

    /// a fake handle for the given module, as returned by LoadLibrary.
    pub fn module_handle(&mut self, dll: &str) -> VA {
        if let Some((&va, _)) = self.modules.iter().find(|(_, name)| *name == dll) {
            return va;
        }
        let va = self.layout.modules.start + 0x10000 * self.modules.len() as u64;
        self.modules.insert(va, dll.to_string());
        va
    }

    pub fn module_name(&self, handle: VA) -> Option<&str> {
        self.modules.get(&handle).map(|s| s.as_str())
    }

    /// read the `index`th argument of the function being called.
    /// assumes the stack pointer points at the return address.
    pub fn arg(&mut self, index: usize) -> u64 {
        match self.arch {
            Arch::X32 => {
                let sp = self.sp();
                self.read_ptr(sp + 4 * (index as u64 + 1)) as u32 as u64
            }
            Arch::X64 => {
                if let Some(&reg) = self.regs.args.get(index) {
                    self.vm.cpu.read_reg(reg)
                } else {
                    // after the return address and 0x20 bytes of shadow space.
                    let sp = self.sp();
                    self.read_ptr(sp + 8 * (index as u64 + 1))
                }
            }
        }
    }

    /// return from the function being called: pop the return address
    /// and `cleanup` bytes of arguments, and set the return value.
    pub fn return_from_call(&mut self, value: u64, cleanup: u64) {
        let sp = self.sp();
        let ret = self.read_ptr(sp);
        self.set_sp(sp + self.pointer_size() + cleanup);
        self.set_return_value(value);
        self.set_pc(ret);
    }

    /// the name of the library function at the given address, if known.
    fn function_name(&self, va: VA) -> Option<&str> {
        self.function_names.get(&va).map(|s| s.as_str())
    }

    pub fn is_executable(&self, va: VA) -> bool {
        self.vm.cpu.mem.get_perm(va) & perm::EXEC != 0
    }

    // --- execution ---

    /// decode the instruction at the given address (cached).
    /// import stubs decode as `Flow::Api` pseudo-instructions.
    pub fn decode(&mut self, va: VA) -> Option<Insn> {
        if self.stubs.contains_key(&va) {
            return Some(Insn::api(va));
        }
        if let Some(insn) = self.insns.get(&va) {
            return insn.clone();
        }
        let buf = self.read_mem(va, 16);
        let insn = Insn::decode(&self.decoder, va, &buf);
        self.insns.insert(va, insn.clone());
        insn
    }

    /// step icicle by exactly one instruction (or one iteration of a `rep` instruction).
    fn step_icicle(&mut self) -> std::result::Result<(), Fault> {
        let pc = self.pc();
        self.stats.instructions += 1;
        let mut exit = self.vm.step(1);
        if let VmExit::UnhandledException((ExceptionCode::SelfModifyingCode, addr)) = exit {
            // icicle doesn't support self-modifying code: it refuses writes to code it has
            // lifted, and won't re-lift an address whose bytes changed (even after restoring
            // a snapshot). so forget all the lifted code and try again.
            self.stats.code_flushes += 1;
            self.vm.code.flush_code();
            let page = addr & !(PAGE_SIZE - 1);
            let exec = self.vm.cpu.mem.get_perm(addr) & perm::EXEC;
            let _ = self
                .vm
                .cpu
                .mem
                .update_perm(page, PAGE_SIZE, perm::READ | perm::WRITE | perm::INIT | exec);
            self.set_pc(pc);
            exit = self.vm.step(1);
        }
        let fault = match exit {
            VmExit::InstructionLimit => return Ok(()),
            VmExit::UnhandledException((code, value)) => match code {
                ExceptionCode::ExecViolation | ExceptionCode::ReadUnmapped => Fault::NotExecutable(value),
                ExceptionCode::InvalidInstruction => Fault::InvalidInstruction(pc),
                _ => Fault::Unsupported(pc, format!("{code:?}")),
            },
            exit => Fault::Unsupported(pc, format!("{exit:?}")),
        };
        if let Fault::Unsupported(_, reason) = &fault {
            let mnemonic = self.vm.get_disasm(pc).unwrap_or("?").split(' ').next().unwrap_or("?").to_string();
            *self.stats.unsupported.entry(format!("{reason}: {mnemonic}")).or_default() += 1;
        }
        Err(fault)
    }

    /// Execute the instruction at the program counter.
    ///
    /// calls to imports, library functions, and (with `CallPolicy::StepOver`)
    /// functions in the program are handled here, so afterwards the program counter
    /// is either at the next instruction, at a branch target, or (with
    /// `CallPolicy::StepInto`) at the first instruction of a callee.
    pub fn execute(&mut self, insn: &Insn, opts: &ExecOptions) -> std::result::Result<Event, Fault> {
        let pc = self.pc();
        if insn.flow == Flow::Api {
            // we got here via a call, a jump (like a thunk), or even a return;
            // in any case, the return address is on the top of the stack.
            let name = self.stubs[&pc].qualified_name();
            self.stats.api_calls += 1;
            return Ok(match api::call(self, pc, &name, opts.api_models) {
                true => Event::Stop,
                false => Event::Executed(None),
            });
        }

        if insn.flow == Flow::Trap {
            return Err(Fault::Trap(pc));
        }

        self.step_icicle()?;

        // a `rep` instruction leaves the program counter in place until it's done.
        if insn.rep {
            let mut iterations = 1;
            while self.pc() == pc {
                if iterations >= opts.rep_max {
                    self.set_pc(pc + insn.len as u64);
                    break;
                }
                self.step_icicle()?;
                iterations += 1;
            }
        }

        if insn.flow != Flow::Call {
            return Ok(Event::Executed(None));
        }

        // follow thunks, like `jmp [__imp_malloc]`, to the function they stand for.
        for _ in 0..4 {
            if !self.thunks.contains(&self.pc()) {
                break;
            }
            self.step_icicle()?;
        }

        let target = self.pc();
        if let Some(stub) = self.stubs.get(&target) {
            return Ok(Event::Executed(Some(Call {
                from: pc,
                target,
                name: Some(stub.qualified_name()),
                kind: CallKind::Api,
            })));
        }

        let name = self.function_name(target).map(|s| s.to_string());
        if opts.api_models {
            if let Some(name) = &name {
                if api::find_model(name).is_some() {
                    if api::call(self, target, name, true) {
                        return Ok(Event::Stop);
                    }
                    return Ok(Event::Executed(Some(Call {
                        from: pc,
                        target,
                        name: Some(name.clone()),
                        kind: CallKind::Library,
                    })));
                }
            }
        }

        if opts.calls == CallPolicy::StepOver || !self.is_executable(target) {
            let cleanup = self.callee_cleanup.get(&target).copied().unwrap_or(0) as u64;
            self.return_from_call(0, cleanup);
            return Ok(Event::Executed(Some(Call {
                from: pc,
                target,
                name,
                kind: CallKind::SteppedOver,
            })));
        }

        Ok(Event::Executed(Some(Call {
            from: pc,
            target,
            name,
            kind: CallKind::Entered,
        })))
    }
}
