//! floss-rs builds its icicle VMs from the embedded SLEIGH specifications
//! (`floss::emu::sleigh::build_vm`), the way icicle builds them from files
//! on disk (`icicle_vm::build_with_path`). Check that the two agree.
use icicle_vm::{
    cpu::{
        mem::{perm, Mapping},
        Config,
    },
    Vm, VmExit,
};

const CODE: u64 = 0x1000;
const STACK: u64 = 0x10000;

fn config(triple: &str) -> Config {
    Config {
        triple: triple.parse().unwrap(),
        enable_shadow_stack: false,
        enable_jit: false,
        optimize_instructions: false,
        optimize_block: false,
        ..Default::default()
    }
}

/// icicle's own build, from the embedded files written to a directory laid out like Ghidra's.
fn from_disk(config: &Config) -> Vm {
    let root = std::env::temp_dir().join(format!("floss-rs-sleigh-test-{}-{}", std::process::id(), config.triple));
    let languages = root.join("x86").join("data").join("languages");
    std::fs::create_dir_all(&languages).unwrap();
    for (name, text) in floss::emu::sleigh::files() {
        std::fs::write(languages.join(name), text).unwrap();
    }
    let vm = icicle_vm::build_with_path(config, &root).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    vm
}

/// run `code` and return the values of `registers`.
fn run(vm: &mut Vm, code: &[u8], registers: &[&str]) -> Vec<u64> {
    let rwx = perm::READ | perm::WRITE | perm::EXEC | perm::INIT;
    vm.cpu.mem.map_memory_len(CODE, 0x1000, Mapping { perm: rwx, value: 0xcc });
    vm.cpu.mem.map_memory_len(STACK, 0x1000, Mapping { perm: rwx, value: 0 });
    vm.cpu.mem.write_bytes(CODE, code, perm::NONE).unwrap();
    vm.cpu.write_reg(vm.cpu.arch.reg_sp, STACK + 0x800);
    vm.cpu.write_pc(CODE);
    assert_eq!(vm.step(4), VmExit::InstructionLimit);
    let reg = |vm: &Vm, n: &str| vm.cpu.arch.sleigh.get_reg(n).unwrap().get_var().unwrap();
    registers.iter().map(|n| vm.cpu.read_reg(reg(vm, n))).collect()
}

fn check(triple: &str, registers: &[&str]) {
    let config = config(triple);
    let mut ours = floss::emu::sleigh::build_vm(&config).unwrap();
    let mut theirs = from_disk(&config);

    let (a, b) = (&ours.cpu.arch, &theirs.cpu.arch);
    assert_eq!(a.reg_pc, b.reg_pc);
    assert_eq!(a.reg_next_pc, b.reg_next_pc);
    assert_eq!(a.reg_sp, b.reg_sp);
    assert_eq!(a.reg_isa_mode, b.reg_isa_mode);
    assert_eq!(a.isa_mode_context, b.isa_mode_context);
    assert_eq!(a.temporaries, b.temporaries);
    assert_eq!(a.sleigh.get_varnode("tmp_pc"), b.sleigh.get_varnode("tmp_pc"));

    // what the setup adds to the compiled SLEIGH: icicle's helper for `rdtsc`, and reading
    // the instruction pointer (`call $+5; pop`), which the lifter patches.
    let code = [
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0x0f, 0x31, // rdtsc
        0xe8, 0x00, 0x00, 0x00, 0x00, // call $+5
        0x58, // pop eax
    ];
    let ours = run(&mut ours, &code, registers);
    let theirs = run(&mut theirs, &code, registers);
    assert_eq!(ours, theirs);
    assert_eq!(ours[0], CODE + 12, "pop the return address");
    assert_eq!(ours[1], 0, "rdtsc's helper");
}

#[test]
fn x86() {
    check("i686-none", &["EAX", "EDX", "ESP"]);
}

#[test]
fn x64() {
    check("x86_64-none", &["RAX", "RDX", "RSP"]);
}
