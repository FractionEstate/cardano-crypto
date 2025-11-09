//! CBOR serialization support
//!
//! Optional CBOR encoding/decoding for cryptographic types.
//! This module is only available with the `cbor` feature flag.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// CBOR serialization trait
pub trait CborSerialize {
    /// Serialize to CBOR bytes
    fn to_cbor(&self) -> Result<Vec<u8>, CborError>;

    /// Deserialize from CBOR bytes
    fn from_cbor(bytes: &[u8]) -> Result<Self, CborError>
    where
        Self: Sized;
}

/// CBOR serialization errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum CborError {
    /// Invalid CBOR encoding
    #[cfg_attr(feature = "thiserror", error("Invalid CBOR encoding"))]
    InvalidEncoding,

    /// Unexpected CBOR structure
    #[cfg_attr(feature = "thiserror", error("Unexpected CBOR structure"))]
    UnexpectedStructure,

    /// Serialization failed
    #[cfg_attr(feature = "thiserror", error("Serialization failed"))]
    SerializationFailed,

    /// Deserialization failed
    #[cfg_attr(feature = "thiserror", error("Deserialization failed"))]
    DeserializationFailed,
}

#[cfg(not(feature = "thiserror"))]
impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::InvalidEncoding => write!(f, "Invalid CBOR encoding"),
            CborError::UnexpectedStructure => write!(f, "Unexpected CBOR structure"),
            CborError::SerializationFailed => write!(f, "Serialization failed"),
            CborError::DeserializationFailed => write!(f, "Deserialization failed"),
        }
    }
}

#[cfg(all(not(feature = "thiserror"), feature = "std"))]
impl std::error::Error for CborError {}

// Note: Actual CBOR implementation will be added when needed
// This can use minicbor, ciborium, or serde_cbor depending on requirements
