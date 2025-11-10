//! VRF-specific constants and suite identifiers
//!
//! Defines cryptographic domain separation constants used in VRF (Verifiable Random Function)
//! implementations. These constants ensure that different cryptographic operations within
//! the VRF produce independent outputs, preventing cross-protocol attacks.
//!
//! # Suite Identifiers
//!
//! VRF suite identifiers uniquely identify the cryptographic parameters:
//! - Elliptic curve (Ed25519)
//! - Hash function (SHA-512)
//! - Hash-to-curve method (Elligator2 or Try-And-Increment)
//!
//! # Security
//!
//! Domain separation is critical for security. Without it, outputs from different
//! parts of the protocol could be confused, potentially leading to attacks.
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::common::vrf_constants::{SUITE_DRAFT03, SUITE_DRAFT13, ONE, TWO, THREE};
//! assert_eq!(SUITE_DRAFT03, 0x04);
//! assert_eq!(SUITE_DRAFT13, 0x03);
//! assert_eq!(ONE, 0x01);
//! assert_eq!(TWO, 0x02);
//! assert_eq!(THREE, 0x03);
//! ```

/// Suite identifier for IETF VRF Draft-03
///
/// Value: `0x04`
///
/// Full name: **ECVRF-ED25519-SHA512-ELL2**
///
/// This suite uses:
/// - Curve: Edwards25519 (Ed25519)
/// - Hash: SHA-512
/// - Hash-to-curve: Elligator2 (simplified, non-uniform)
/// - Proof size: 80 bytes
///
/// This is the **primary VRF variant** used in Cardano for:
/// - Block production leader selection
/// - Epoch nonce generation
/// - Praos consensus protocol
pub const SUITE_DRAFT03: u8 = 0x04;

/// Suite identifier for IETF VRF Draft-13
///
/// Value: `0x03`
///
/// Full name: **ECVRF-ED25519-SHA512-TAI**
///
/// This suite uses:
/// - Curve: Edwards25519 (Ed25519)
/// - Hash: SHA-512
/// - Hash-to-curve: Try-And-Increment (uniform, slower)
/// - Proof size: 128 bytes (includes full challenge)
///
/// This variant provides:
/// - Batch verification support
/// - Uniform hash-to-curve distribution
/// - Compatibility with RFC 9381 (newer standard)
pub const SUITE_DRAFT13: u8 = 0x03;

/// Domain separation constant: Hash-to-curve operation
///
/// Value: `0x01`
///
/// Used as a prefix when hashing messages to curve points. This ensures
/// that hash-to-curve outputs cannot be confused with other protocol elements.
///
/// Appears in: `SHA-512(suite || ONE || public_key || message)`
pub const ONE: u8 = 0x01;

/// Domain separation constant: Challenge generation
///
/// Value: `0x02`
///
/// Used when computing the Fiat-Shamir challenge in proof generation and verification.
/// This prevents challenge values from being confused with other hash outputs.
///
/// Appears in: `SHA-512(suite || TWO || ...proof elements...)`
pub const TWO: u8 = 0x02;

/// Domain separation constant: VRF output computation
///
/// Value: `0x03`
///
/// Used when deriving the final VRF output from the proof. This ensures the
/// VRF output is independent from internal proof components.
///
/// Appears in: `SHA-512(suite || THREE || proof_to_hash(...))`
pub const THREE: u8 = 0x03;

