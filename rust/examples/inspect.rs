//! print what floss-rs sees in a program: functions, blocks, callers, features.
//! usage: inspect <pe> [function-va-hex]
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let buf = std::fs::read(&args[1])?;
    let ws = floss::workspace::Workspace::from_pe(&buf, &[])?;
    let features = floss::features::find_decoding_function_features(&ws);
    match args.get(2) {
        None => {
            for f in ws.functions() {
                println!(
                    "{:#x} blocks={} insns={} callers={} name={:?} thunk={} score={:?}",
                    f.va,
                    f.blocks.len(),
                    f.insns().count(),
                    ws.callers(f.va).count(),
                    ws.name(f.va),
                    ws.is_thunk(f.va),
                    features.get(&f.va).map(|f| f.score)
                );
            }
        }
        Some(va) => {
            let va = u64::from_str_radix(va.trim_start_matches("0x"), 16)?;
            if let Some(f) = ws.function(va) {
                for bb in f.blocks.values() {
                    println!("block {:#x}: {} insns, last {:#x}, succs {:x?}", bb.va, bb.insns.len(), bb.last_insn(), bb.successors);
                }
            }
            for c in ws.callers(va) {
                println!("caller: {c:#x} in {:x?}", ws.function_containing(c));
            }
            if let Some(f) = features.get(&va) {
                for feat in f.features.iter() {
                    println!("  {feat:x?}");
                }
                println!("  score: {}", f.score);
            }
        }
    }
    Ok(())
}
