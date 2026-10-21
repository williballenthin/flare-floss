//! A stand-in for icicle's JIT (`icicle-jit`), for the browser build.
//!
//! icicle's VM always creates a JIT, which generates machine code with cranelift
//! and maps it executable, which a browser can't do. floss-rs never enables the
//! JIT, so this provides the same API, compiling nothing: a VM that tried to
//! use it would fall back to the interpreter.
use std::collections::HashMap;

use icicle_cpu::{lifter::Block as IcicleBlock, Cpu};

pub type JitFunction = unsafe extern "C" fn(*mut Cpu, u64) -> u64;

pub struct CompilationTarget<'a> {
    pub blocks:  &'a [IcicleBlock],
    pub targets: &'a [usize],
}

impl<'a> CompilationTarget<'a> {
    pub fn new(blocks: &'a [IcicleBlock], targets: &'a [usize]) -> Self {
        Self { blocks, targets }
    }
}

#[derive(Debug)]
pub struct Unsupported;

#[derive(Default)]
pub struct JIT {
    pub il_dump:      Option<String>,
    pub jit_hit:      u64,
    pub jit_miss:     u64,
    pub entry_points: HashMap<u64, JitFunction>,
    pub dead:         usize,
}

impl JIT {
    pub fn new(_cpu: &Cpu) -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {}

    /// # Safety
    /// nothing to reset.
    pub unsafe fn reset(&mut self) {}

    pub fn should_purge(&self) -> bool {
        false
    }

    pub fn invalidate(&mut self, _block_id: usize) {}

    pub fn lookup_fast(&self, _addr: u64) -> Option<JitFunction> {
        None
    }

    pub fn add_fast_lookup(&mut self, _addr: u64, _entry: JitFunction) {}

    pub fn remove_fast_lookup(&mut self, _addr: u64) {}

    pub fn clear_fast_lookup(&mut self) {}

    pub fn compile(&mut self, _target: &CompilationTarget) -> Result<(), Unsupported> {
        Err(Unsupported)
    }
}

/// what a VM calls instead of JIT'd code: these are icicle's own.
pub mod runtime {
    use icicle_cpu::{Cpu, ExceptionCode, InternalError};

    /// # Safety
    /// `cpu` is the VM's CPU.
    pub unsafe extern "C" fn jit_compilation_error(cpu: *mut Cpu, addr: u64) -> u64 {
        (*cpu).exception.code = ExceptionCode::JitError as u32;
        addr
    }

    /// # Safety
    /// `cpu` is the VM's CPU.
    pub unsafe extern "C" fn address_not_translated(cpu: *mut Cpu, addr: u64) -> u64 {
        (*cpu).exception.code = ExceptionCode::CodeNotTranslated as u32;
        (*cpu).exception.value = addr;
        addr
    }

    /// # Safety
    /// `cpu` is the VM's CPU.
    pub unsafe extern "C" fn switch_to_interpreter(cpu: *mut Cpu, addr: u64) -> u64 {
        (*cpu).exception = (ExceptionCode::InternalError, InternalError::SwitchToInterpreter).into();
        addr
    }
}
