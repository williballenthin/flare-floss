//! micro-benchmarks of emulator primitives on a real program.
//! usage: bench <pe>
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let buf = std::fs::read(&args[1])?;
    let ws = floss::workspace::Workspace::from_pe(&buf, &[])?;
    let mut emu = floss::emu::Emulator::new(&ws)?;
    let fva = ws.functions().next().unwrap().va;
    emu.reset(fva);

    let n: u32 = std::env::var("N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let t = std::time::Instant::now();
    let snaps: Vec<_> = (0..n).map(|_| emu.snapshot()).collect();
    println!("snapshot: {:?} each", t.elapsed() / n);

    let t = std::time::Instant::now();
    for s in snaps.iter() {
        emu.restore(s);
    }
    println!("restore: {:?} each", t.elapsed() / n);

    let t = std::time::Instant::now();
    for _ in 0..n {
        emu.reset(fva);
    }
    println!("reset: {:?} each", t.elapsed() / n);

    let t = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = emu.memory();
    }
    println!("memory view: {:?} each", t.elapsed() / 1000);
    Ok(())
}
