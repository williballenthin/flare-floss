//! The x86 SLEIGH specifications, embedded into the binary.
//!
//! icicle compiles the processor specification from files on disk,
//! so on first use we write the embedded files to a directory in the
//! system temp directory, named by the hash of their contents.
use std::path::PathBuf;

use anyhow::{Context, Result};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/sleigh_files.rs"));
}

/// FNV-1a, so the directory name changes whenever the specs change.
fn content_hash() -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for (name, data) in embedded::FILES {
        for b in name.bytes().chain(data.iter().copied()) {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// Returns a directory laid out like Ghidra's `Ghidra/Processors`,
/// suitable for `icicle_vm::build_with_path`.
pub fn processors_dir() -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!("floss-rs-sleigh-{:016x}", content_hash()));
    let languages = root.join("x86").join("data").join("languages");
    if languages.join("x86.ldefs").exists() {
        return Ok(root);
    }

    // write to a private directory and rename it into place,
    // so that concurrent processes never see a partial directory.
    let staging = std::env::temp_dir().join(format!("floss-rs-sleigh-staging-{}", std::process::id()));
    let staging_languages = staging.join("x86").join("data").join("languages");
    std::fs::create_dir_all(&staging_languages).context("create SLEIGH staging directory")?;
    for (name, data) in embedded::FILES {
        std::fs::write(staging_languages.join(name), data).context("write SLEIGH file")?;
    }
    if std::fs::rename(&staging, &root).is_err() {
        // another process won the race; use its copy.
        let _ = std::fs::remove_dir_all(&staging);
    }
    Ok(root)
}
