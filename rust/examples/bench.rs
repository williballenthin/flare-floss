//! measure the costs of emulation primitives on a real program:
//! exploring every function twice, so the second time the code is already lifted.
//! usage: bench <pe>
use floss::{driver, emu};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let buf = std::fs::read(&args[1])?;
    let t = std::time::Instant::now();
    let ws = floss::workspace::Workspace::from_pe(&buf, &[])?;
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
