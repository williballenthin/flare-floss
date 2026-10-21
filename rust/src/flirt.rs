//! FLIRT signatures, to recognize library functions: FLOSS's own
//! (`floss/sigs`), built into the binary, or files given on the command line.
use std::{borrow::Cow, path::Path};

use anyhow::{Context, Result};
use lancelot::{workspace::config::Configuration, VA};
use lancelot_flirt::{FlirtSignature, FlirtSignatureSet};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/flirt_files.rs"));
}

/// A file of FLIRT signatures: its name, whose extension gives the format
/// (`.sig` or `.pat`), and its contents.
#[derive(Debug, Clone)]
pub struct SignatureFile {
    pub name: String,
    pub data: Cow<'static, [u8]>,
}

impl SignatureFile {
    pub fn read(path: &Path) -> Result<SignatureFile> {
        Ok(SignatureFile {
            name: path.to_string_lossy().into_owned(),
            data: Cow::Owned(std::fs::read(path).with_context(|| format!("read {}", path.display()))?),
        })
    }
}

/// FLOSS's signatures, which are built into the binary.
pub fn builtin() -> Vec<SignatureFile> {
    embedded::FILES
        .iter()
        .map(|(name, data)| SignatureFile {
            name: name.to_string(),
            data: Cow::Borrowed(data),
        })
        .collect()
}

/// lancelot's configuration for analyzing a program: signatures from memory, and no function hints.
pub(crate) struct Signatures(pub Vec<SignatureFile>);

impl Configuration for Signatures {
    fn get_sigs(&self) -> Result<FlirtSignatureSet> {
        let mut sigs: Vec<FlirtSignature> = vec![];
        for file in &self.0 {
            if file.name.ends_with(".sig") {
                sigs.extend(lancelot_flirt::sig::parse(&file.data)?);
            } else if file.name.ends_with(".pat") {
                sigs.extend(lancelot_flirt::pat::parse(std::str::from_utf8(&file.data)?)?);
            }
        }
        Ok(FlirtSignatureSet::with_signatures(sigs))
    }

    fn get_function_hints(&self) -> Result<Vec<VA>> {
        Ok(vec![])
    }

    fn clone(&self) -> Box<dyn Configuration> {
        Box::new(Signatures(self.0.clone()))
    }
}
