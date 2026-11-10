//! measure the costs of emulation primitives on a real program:
//! exploring every function twice, so the second time the code is already lifted.
//! usage: bench <ida|lancelot> <file>
use anyhow::{bail, Result};
use floss::{driver, emu, program::Program};

fn load(backend: &str, path: &std::path::Path) -> Result<Program> {
    match backend {
        #[cfg(feature = "ida")]
        "ida" => floss::backend::ida::load(path, &Default::default()),
        #[cfg(feature = "lancelot")]
        "lancelot" => floss::backend::lancelot::load_pe(&std::fs::read(path)?, &[]),
        _ => bail!("this build doesn't have the backend {backend}"),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!("usage: bench <ida|lancelot> <file>");
    }
    let t = std::time::Instant::now();
    let program = load(&args[1], std::path::Path::new(&args[2]))?;
    println!("program ({}): {:?}", args[1], t.elapsed());
    let t = std::time::Instant::now();
    let ws = floss::workspace::Workspace::new(program);
    println!("workspace: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let mut emu = emu::Emulator::new(&ws)?;
    println!("emulator (SLEIGH compile + mapping): {:?}", t.elapsed());

    let opts = emu::ExecOptions {
        calls:      emu::CallPolicy::StepOver,
        api_models: false,
        rep_max:    256,
    };
    let functions: Vec<u64> = ws.functions().map(|f| f.va).collect();
    for round in ["cold (lifting)", "warm (cached)"] {
        let before = emu.stats.clone();
        let t = std::time::Instant::now();
        for &f in functions.iter() {
            emu.reset(f);
            driver::explore(&mut emu, &opts, &mut driver::Nothing);
        }
        let el = t.elapsed();
        let insns = emu.stats.instructions - before.instructions;
        let snaps = emu.stats.snapshots - before.snapshots;
        println!(
            "{round}: {} functions, {insns} instructions, {snaps} snapshots, {el:?}: {:.2}µs/instruction",
            functions.len(),
            el.as_secs_f64() * 1e6 / insns as f64
        );
    }
    Ok(())
}
