//! Single-period KES implementations
//!
//! This module provides two variants of single-period KES:
//! - `basic`: Standard single-period KES wrapping a digital signature algorithm
//! - `compact`: Single-period KES with embedded verification key in signature

pub mod basic;
pub mod compact;

pub use basic::SingleKes;
pub use compact::{CompactSingleKes, CompactSingleSig, OptimizedKesSignature};
