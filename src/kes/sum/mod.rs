//! SumKES - Binary tree composition implementations
//!
//! This module provides binary tree composition of KES schemes:
//! - `basic`: Standard SumKES with explicit verification keys
//! - `compact`: Space-optimized CompactSumKES
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::kes::{Sum2Kes, Sum6Kes};
//! // Import the trait so `total_periods` is available for the doctest
//! use cardano_crypto::kes::KesAlgorithm;
//! // Check periods
//! assert_eq!(Sum2Kes::total_periods(), 4);
//! assert_eq!(Sum6Kes::total_periods(), 64);
//! ```

pub mod basic;
pub mod compact;

pub use basic::{
    Sum0Kes, Sum1Kes, Sum2Kes, Sum3Kes, Sum4Kes, Sum5Kes, Sum6Kes, Sum7Kes, SumKes, SumSignature,
    SumSigningKey,
};

pub use compact::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes, CompactSum5Kes,
    CompactSum6Kes, CompactSum7Kes, CompactSumKes, CompactSumSignature, CompactSumSigningKey,
};
