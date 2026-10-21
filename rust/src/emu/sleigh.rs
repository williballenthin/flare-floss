//! The x86 SLEIGH specifications, embedded into the binary, and icicle VMs built from them.
//!
//! icicle builds a VM from a directory of Ghidra processor specifications
//! (`icicle_vm::build_with_path`). floss-rs builds it from memory instead,
//! so the binary needs no files at runtime: it compiles the embedded
//! specifications with icicle's SLEIGH compiler, and then sets up the VM
//! the way `build_with_path` does for x86. `tests/sleigh.rs` checks that the two agree.
use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use icicle_vm::{
    cpu::{
        cpu::CallCov,
        exec::helpers::{self, PcodeOpHelper},
        lifter, Arch, Config, Cpu, ValueSource,
    },
    Vm,
};
use serde::Deserialize;
use sleigh_compile::ldef::LanguageDef;
use target_lexicon::Architecture;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/sleigh_files.rs"));
}

/// The embedded specification files, by name, like `x86.ldefs` and `ia.sinc`.
pub fn files() -> &'static [(&'static str, &'static str)] {
    embedded::FILES
}

fn file(name: &str) -> Result<&'static str> {
    files()
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, text)| *text)
        .ok_or_else(|| anyhow!("no SLEIGH file {name}"))
}

/// The parts of a processor specification (`.pspec`) that icicle uses.
#[derive(Deserialize)]
struct ProcessorSpec {
    programcounter: Register,
    #[serde(default)]
    context_data: ContextData,
}

/// The part of a compiler specification (`.cspec`) that icicle uses.
#[derive(Deserialize)]
struct CompilerSpec {
    stackpointer: Register,
}

#[derive(Deserialize)]
struct Register {
    #[serde(rename = "@register")]
    register: String,
}

#[derive(Default, Deserialize)]
struct ContextData {
    context_set: Option<ContextSet>,
}

#[derive(Deserialize)]
struct ContextSet {
    #[serde(rename = "#content", default)]
    set: Vec<ContextValue>,
}

#[derive(Deserialize)]
struct ContextValue {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@val")]
    val: u64,
}

/// Build an x86 or x64 VM, like `icicle_vm::build_with_path` with Ghidra's `x86` processor.
pub fn build_vm(config: &Config) -> Result<Vm> {
    let id = match config.triple.architecture {
        Architecture::X86_32(_) => "x86:LE:32:default",
        Architecture::X86_64 => "x86:LE:64:default",
        _ => return Err(anyhow!("unsupported architecture: {}", config.triple)),
    };

    // the language, from the language definitions, like icicle's `sleigh_compile::ldef::build`.
    let ldefs: LanguageDef = serde_xml_rs::from_str(file("x86.ldefs")?).context("parse x86.ldefs")?;
    let language = ldefs.find_match(id).ok_or_else(|| anyhow!("no language {id}"))?;
    let pspec: ProcessorSpec =
        serde_xml_rs::from_str(file(&language.processorspec)?).context("parse the processor specification")?;
    // the default compiler, or else gcc, like icicle.
    let compiler = ["default", "gcc"]
        .iter()
        .find_map(|c| language.compiler.iter().find(|x| x.id == *c || x.name == *c))
        .ok_or_else(|| anyhow!("no compiler specification for {id}"))?;
    let cspec: CompilerSpec =
        serde_xml_rs::from_str(file(&compiler.spec)?).context("parse the compiler specification")?;

    let sources: HashMap<String, String> = files().iter().map(|(n, t)| (n.to_string(), t.to_string())).collect();
    let mut parser = sleigh_parse::Parser::new(sources, &["ICICLE"]);
    let slaspec = format!("{}.slaspec", language.slafile.trim_end_matches(".sla"));
    parser
        .include_file(slaspec)
        .map_err(|e| anyhow!("{}", parser.error_formatter(e)))?;
    let mut sleigh = sleigh_compile::build_inner(parser, false).map_err(|e| anyhow!("compile SLEIGH: {e}"))?;

    let mut initial_ctx = 0;
    for value in pspec.context_data.context_set.map(|c| c.set).unwrap_or_default() {
        let field = sleigh
            .get_context_field(&value.name)
            .ok_or_else(|| anyhow!("no context field {}", value.name))?;
        field.field.set(&mut initial_ctx, value.val as i64);
    }
    let register = |name: &str| sleigh.get_varnode(name).ok_or_else(|| anyhow!("no register {name}"));
    let reg_pc = register(&pspec.programcounter.register)?;
    let reg_sp = register(&cspec.stackpointer.register)?;
    let temporaries = ["xmmTmp1", "xmmTmp2"]
        .iter()
        .map(|name| Ok(register(name)?.id))
        .collect::<Result<Vec<_>>>()?;
    let reg_next_pc = sleigh
        .add_custom_reg("NEXT_PC", 8)
        .ok_or_else(|| anyhow!("add NEXT_PC"))?;

    // the VM, like icicle's `build_with_path` and `build_vm`.
    let arch = Arch {
        triple: config.triple.clone(),
        reg_pc,
        reg_next_pc,
        reg_sp,
        reg_isa_mode: None,
        isa_mode_context: vec![initial_ctx],
        reg_init: vec![],
        temporaries: temporaries.clone(),
        // floss-rs reads arguments itself, so the calling convention isn't needed.
        calling_cov: CallCov {
            integers:     vec![],
            stack_align:  4,
            stack_offset: 0,
        },
        on_boot,
        sleigh,
    };
    let mut cpu = Cpu::new_boxed(arch);
    cpu.enable_shadow_stack = config.enable_shadow_stack;
    cpu.mem.track_uninitialized = config.track_uninitialized;

    let settings = lifter::Settings {
        optimize: config.optimize_instructions,
        optimize_block: config.optimize_block,
        ..Default::default()
    };
    let mut block_lifter = lifter::BlockLifter::new(settings, lifter::InstructionLifter::new());
    for var in temporaries {
        block_lifter.mark_as_temporary(var);
    }
    let mut vm = Vm::new(cpu, block_lifter);
    vm.enable_jit = config.enable_jit;

    lifter::get_injectors(&mut vm.cpu, &mut vm.lifter.op_injectors);
    register_helpers(&mut vm, helpers::HELPERS);
    register_helpers(&mut vm, helpers::x86::HELPERS);

    // instructions that read the instruction pointer see the address of the next instruction.
    let tmp_pc = vm
        .cpu
        .arch
        .sleigh
        .add_custom_reg("tmp_pc", reg_pc.size)
        .ok_or_else(|| anyhow!("add tmp_pc"))?;
    vm.lifter.mark_as_temporary(tmp_pc.id);
    vm.lifter
        .patchers
        .push(lifter::read_pc_patcher(reg_pc, tmp_pc, false));

    Ok(vm)
}

fn on_boot(cpu: &mut Cpu, entry: u64) {
    cpu.reset();
    cpu.regs.write_trunc(cpu.arch.reg_pc, entry);
}

fn register_helpers(vm: &mut Vm, helpers: &[(&str, PcodeOpHelper)]) {
    for &(name, helper) in helpers {
        if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
            vm.cpu.set_helper(id, helper);
        }
    }
}
