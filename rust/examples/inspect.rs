//! print what floss-rs sees in a program: segments, imports, functions, blocks, callers, features.
//! usage: inspect <ida|lancelot> <file> [function-va-hex]
use anyhow::{bail, Result};
use floss::program::Program;

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
        bail!("usage: inspect <ida|lancelot> <file> [function-va-hex]");
    }
    let ws = floss::workspace::Workspace::new(load(&args[1], std::path::Path::new(&args[2]))?);
    let features = floss::features::find_decoding_function_features(&ws);
    match args.get(3) {
        None => {
            println!("arch={:?} base={:#x}", ws.arch(), ws.base_address());
            for s in ws.segments() {
                let sum = s
                    .bytes
                    .iter()
                    .fold(0u32, |sum, &b| sum.wrapping_mul(31).wrapping_add(b as u32));
                println!(
                    "segment {:#x}-{:#x} {} exec={} sum={sum:08x}",
                    s.va,
                    s.end(),
                    s.name,
                    s.executable
                );
            }
            for i in ws.imports() {
                println!("import {:#x} {}.{}", i.va, i.dll, i.name);
            }
            for f in ws.functions() {
                println!(
                    "{:#x} blocks={} insns={} callers={} name={:?} thunk={} library={} score={:?}",
                    f.va,
                    f.blocks.len(),
                    f.insns().count(),
                    ws.callers(f.va).count(),
                    ws.name(f.va),
                    ws.is_thunk(f.va),
                    ws.is_library(f.va),
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
