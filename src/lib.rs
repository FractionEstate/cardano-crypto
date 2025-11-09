//! # Cardano Crypto
//!
//! Pure Rust implementation of Cardano cryptographic primitives.
//!
//! This crate provides a unified interface for all Cardano cryptographic operations:
//! - **VRF** (Verifiable Random Functions) - IETF Draft-03 and Draft-13
//! - **KES** (Key Evolving Signatures) - Forward-secure signature schemes
//! - **DSIGN** (Digital Signatures) - Ed25519 and variants
//! - **Hash** - Blake2b, SHA-2, and other Cardano hash functions
//! - **Seed** - Deterministic key derivation
//! - **CBOR** - Optional serialization support
//!
//! # Feature Flags
//!
//! This crate uses feature flags to allow selective compilation:
//!
//! - `std` (default) - Standard library support
//! - `alloc` - Allocation support for no_std
//! - `vrf` - VRF implementations (includes `dsign`, `hash`)
//! - `kes` - KES implementations (includes `dsign`, `hash`)
//! - `dsign` - Digital signature algorithms (includes `hash`)
//! - `hash` - Hash functions
//! - `cbor` - CBOR serialization
//! - `serde` - Serde serialization for keys/signatures
//! - `metrics` - Performance metrics collection
//! - `logging` - Debug logging support
//!
//! # Examples
//!
//! ## VRF Proof Generation
//!
//! ```rust,ignore
//! use cardano_crypto::vrf::{VrfDraft03, VrfKeyPair};
//!
//! let seed = [0u8; 32];
//! let keypair = VrfKeyPair::from_seed(&seed);
//! let proof = keypair.prove(b"message")?;
//! let output = proof.verify(&keypair.public_key(), b"message")?;
//! ```
//!
//! ## KES Signing
//!
//! ```rust,ignore
//! use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};
//!
//! let seed = [0u8; 32];
//! let signing_key = Sum6Kes::gen_key_from_seed(&seed)?;
//! let signature = Sum6Kes::sign(&signing_key, 0, b"message")?;
//! ```
//!
//! ## Digital Signatures
//!
//! ```rust,ignore
//! use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//!
//! let seed = [0u8; 32];
//! let signing_key = Ed25519::gen_key(&seed);
//! let signature = Ed25519::sign(&signing_key, b"message");
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::all
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// ============================================================================
// Common utilities and traits
// ============================================================================

pub mod common;

// ============================================================================
// Core cryptographic components
// ============================================================================

#[cfg(feature = "hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "hash")))]
pub mod hash;

#[cfg(feature = "seed")]
#[cfg_attr(docsrs, doc(cfg(feature = "seed")))]
pub mod seed;

#[cfg(feature = "dsign")]
#[cfg_attr(docsrs, doc(cfg(feature = "dsign")))]
pub mod dsign;

#[cfg(feature = "vrf")]
#[cfg_attr(docsrs, doc(cfg(feature = "vrf")))]
pub mod vrf;

#[cfg(feature = "kes")]
#[cfg_attr(docsrs, doc(cfg(feature = "kes")))]
pub mod kes;

#[cfg(feature = "cbor")]
#[cfg_attr(docsrs, doc(cfg(feature = "cbor")))]
pub mod cbor;

// ============================================================================
// Re-exports for convenience
// ============================================================================

#[cfg(feature = "hash")]
pub use hash::{Blake2b224, Blake2b256, Blake2b512, HashAlgorithm};

#[cfg(feature = "dsign")]
pub use dsign::{DsignAlgorithm, Ed25519};

#[cfg(feature = "vrf")]
pub use vrf::VrfDraft03;

#[cfg(feature = "kes")]
pub use kes::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes,
    CompactSum5Kes, CompactSum6Kes, CompactSum7Kes, KesAlgorithm, SingleKes, Sum0Kes, Sum1Kes,
    Sum2Kes, Sum3Kes, Sum4Kes, Sum5Kes, Sum6Kes, Sum7Kes,
};

// ============================================================================
// Crate metadata
// ============================================================================

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name
pub const NAME: &str = env!("CARGO_PKG_NAME");
