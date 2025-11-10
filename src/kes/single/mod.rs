//! Single-period KES implementations
//!
//! This module provides two variants of single-period KES:
//! - `basic`: Standard single-period KES wrapping a digital signature algorithm
//! - `compact`: Single-period KES with embedded verification key in signature
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::kes::{SingleKes, CompactSingleKes};
//! // Import the trait so associated constants are available in this doctest
//! use cardano_crypto::kes::KesAlgorithm;
//! // Types are available for use; just assert their associated constants compile
//! assert_eq!(SingleKes::<cardano_crypto::dsign::Ed25519>::SEED_SIZE, 32);
//! assert_eq!(CompactSingleKes::<cardano_crypto::dsign::Ed25519>::SEED_SIZE, 32);
//! ```

pub mod basic;
pub mod compact;

pub use basic::SingleKes;
pub use compact::{
    CompactKesComponents, CompactSingleKes, CompactSingleSig, OptimizedKesSignature,
};

