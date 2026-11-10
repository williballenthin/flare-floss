//! Program analysis backends: each loads a program and describes it as a `crate::program::Program`,
//! with its segments, functions, control flow, and imports.
//!
//! The backends are cargo features, and a build can have both.

#[cfg(feature = "ida-database")]
pub mod ida;
#[cfg(feature = "lancelot")]
pub mod lancelot;
