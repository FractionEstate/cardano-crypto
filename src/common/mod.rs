//! Common cryptographic utilities shared across implementations
//!
//! This module provides low-level cryptographic primitives used by
//! VRF, KES, and DSIGN implementations, organized into submodules:
//!
//! - [`error`] - Error types and result aliases
//! - [`curve`] - Edwards curve point and scalar operations
//! - [`hash`] - Hashing utilities (SHA-512, etc.)
//! - [`traits`] - Common traits (SignableRepresentation, ConstantTimeEq)
//! - [`security`] - Security utilities (zeroize, etc.)
//! - [`vrf_constants`] - VRF suite identifiers and domain separation constants

pub mod error;

#[cfg(feature = "vrf")]
pub mod curve;

#[cfg(feature = "vrf")]
pub mod hash;

pub mod traits;
/// Security-related utilities and constant-time operations
pub mod security;

#[cfg(feature = "vrf")]
pub mod vrf_constants;

// Re-export commonly used types and functions
pub use error::{CryptoError, CryptoResult};

#[cfg(feature = "vrf")]
pub use curve::{bytes_to_point, bytes_to_scalar, clamp_scalar, point_to_bytes, scalar_to_bytes};

#[cfg(feature = "vrf")]
pub use hash::hash_sha512;

pub use traits::{ConstantTimeEq, SignableRepresentation};
pub use security::zeroize;

#[cfg(feature = "vrf")]
pub use vrf_constants::{ONE, SUITE_DRAFT03, SUITE_DRAFT13, THREE, TWO};

/// Deprecated alias for backwards compatibility
pub type Result<T> = core::result::Result<T, CryptoError>;
