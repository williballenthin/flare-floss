//! The strings FLOSS finds, shaped like FLOSS's `results.py` so the JSON is comparable.
use serde::Serialize;

use crate::{emu::snapshot::Region, strings::Encoding};

/// A string constructed on the stack, found while emulating a function.
///
/// ```text
///     [smaller addresses]
///
///     +---------------+  <- stack_pointer (top of stack)
///     |               | \
///     +---------------+  | offset
///     |               | /
///     +---------------+
///     | "abc"         | \
///     +---------------+  |
///     |               |  |
///     +---------------+  | frame_offset
///     |               |  |
///     +---------------+  |
///     |               | /
///     +---------------+  <- original_stack_pointer (bottom of stack, probably bp)
///
///     [bigger addresses]
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct StackString {
    pub function:               u64,
    pub string:                 String,
    pub encoding:               Encoding,
    /// the address of the instruction where the string was found.
    pub program_counter:        u64,
    pub stack_pointer:          u64,
    pub original_stack_pointer: u64,
    pub offset:                 u64,
    pub frame_offset:           u64,
}

/// A stack string that's decoded by a tight loop; same shape as a stack string.
pub type TightString = StackString;

#[derive(Debug, Clone, Copy, Serialize)]
pub enum AddressType {
    #[serde(rename = "STACK")]
    Stack,
    #[serde(rename = "GLOBAL")]
    Global,
    #[serde(rename = "HEAP")]
    Heap,
}

impl From<Region> for AddressType {
    fn from(region: Region) -> AddressType {
        match region {
            Region::Stack => AddressType::Stack,
            Region::Global => AddressType::Global,
            Region::Heap => AddressType::Heap,
        }
    }
}

/// A string written to memory by a decoding routine.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedString {
    pub address:          u64,
    pub address_type:     AddressType,
    pub string:           String,
    pub encoding:         Encoding,
    /// the address of the call to the decoding routine.
    pub decoded_at:       u64,
    pub decoding_routine: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaticString {
    pub string:   String,
    pub offset:   u64,
    pub encoding: Encoding,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Strings {
    pub static_strings:  Vec<StaticString>,
    pub stack_strings:   Vec<StackString>,
    pub tight_strings:   Vec<TightString>,
    pub decoded_strings: Vec<DecodedString>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Runtime {
    pub workspace:       f64,
    pub find_features:   f64,
    pub static_strings:  f64,
    pub stack_strings:   f64,
    pub tight_strings:   f64,
    pub decoded_strings: f64,
    pub total:           f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub functions_discovered:            usize,
    pub functions_library:               usize,
    pub functions_analyzed_stack_strings: usize,
    pub functions_analyzed_tight_strings: usize,
    pub functions_analyzed_decoded_strings: usize,
    /// functions that could have been emulated as decoding routines.
    pub decoding_candidates:             usize,
    /// the candidate decoding routines that were emulated, in order.
    pub decoding_routines:               Vec<DecodingRoutine>,
}

/// A candidate decoding routine, and what emulating it cost.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DecodingRoutine {
    pub address: u64,
    pub score:   f64,
    /// one of the candidates that are always emulated (the top-scoring ones, and tight functions).
    pub required: bool,
    /// call contexts it was emulated from.
    pub calls:   usize,
    /// decoded strings it reported, which are listed in order in `decoded_strings`.
    pub strings: usize,
    pub seconds: f64,
    /// the features that made it a candidate, as counts.
    pub features: std::collections::BTreeMap<&'static str, usize>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Metadata {
    pub file_path: String,
    pub imagebase: u64,
    pub min_length: usize,
    pub runtime:   Runtime,
    pub emulation: crate::emu::Stats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResultDocument {
    pub metadata: Metadata,
    pub analysis: Analysis,
    pub strings:  Strings,
}
