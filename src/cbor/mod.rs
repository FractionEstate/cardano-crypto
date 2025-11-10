//! CBOR serialization support
//!
//! Provides CBOR encoding/decoding for cryptographic types following the Cardano specification.
//!
//! The CBOR format used matches the Haskell cardano-base implementation:
//! - Verification keys: CBOR-encoded raw bytes
//! - Signatures: CBOR-encoded raw bytes
//! - Signing keys: Not serialized in production (security risk)
//!
//! This module provides a simple wrapper around raw serialization that adds CBOR
//! byte string encoding, matching the behavior of `encodeBytes` in Haskell's
//! `Cardano.Binary` module.
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::cbor::{encode_bytes, decode_bytes};
//!
//! # fn main() -> Result<(), cardano_crypto::cbor::CborError> {
//! // Encode data as CBOR byte string
//! let data = b"verification key data";
//! let cbor_encoded = encode_bytes(data);
//!
//! // Decode CBOR byte string
//! let decoded = decode_bytes(&cbor_encoded)?;
//! assert_eq!(data, &decoded[..]);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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

    /// Invalid byte length
    #[cfg_attr(feature = "thiserror", error("Invalid byte length"))]
    InvalidLength,

    /// Buffer too small
    #[cfg_attr(feature = "thiserror", error("Buffer too small"))]
    BufferTooSmall,
}

#[cfg(not(feature = "thiserror"))]
impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::InvalidEncoding => write!(f, "Invalid CBOR encoding"),
            CborError::UnexpectedStructure => write!(f, "Unexpected CBOR structure"),
            CborError::SerializationFailed => write!(f, "Serialization failed"),
            CborError::DeserializationFailed => write!(f, "Deserialization failed"),
            CborError::InvalidLength => write!(f, "Invalid byte length"),
            CborError::BufferTooSmall => write!(f, "Buffer too small"),
        }
    }
}

#[cfg(all(not(feature = "thiserror"), feature = "std"))]
impl std::error::Error for CborError {}

/// Encode bytes as CBOR byte string (major type 2)
///
/// This matches the behavior of `encodeBytes` from Haskell's Cardano.Binary module.
///
/// CBOR byte strings use major type 2:
/// - For length < 24: single byte header
/// - For length < 256: header + 1 byte length
/// - For length < 65536: header + 2 bytes length
/// - For length < 2^32: header + 4 bytes length
#[cfg(feature = "alloc")]
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut result = Vec::new();

    // Encode CBOR header based on length
    if len < 24 {
        // Short form: header byte contains length directly
        result.push(0x40 | len as u8); // Major type 2, additional info = length
    } else if len < 256 {
        // 1-byte length
        result.push(0x58); // Major type 2, additional info = 24 (1-byte uint follows)
        result.push(len as u8);
    } else if len < 65536 {
        // 2-byte length
        result.push(0x59); // Major type 2, additional info = 25 (2-byte uint follows)
        result.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        // 4-byte length (for very large keys/signatures)
        result.push(0x5a); // Major type 2, additional info = 26 (4-byte uint follows)
        result.extend_from_slice(&(len as u32).to_be_bytes());
    }

    result.extend_from_slice(bytes);
    result
}

/// Decode CBOR byte string (major type 2)
///
/// This matches the behavior of `decodeBytes` from Haskell's Cardano.Binary module.
#[cfg(feature = "alloc")]
pub fn decode_bytes(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    if cbor.is_empty() {
        return Err(CborError::InvalidEncoding);
    }

    let header = cbor[0];
    let major_type = (header >> 5) & 0x07;

    // Must be major type 2 (byte string)
    if major_type != 2 {
        return Err(CborError::UnexpectedStructure);
    }

    let additional_info = header & 0x1f;

    let (length, offset) = if additional_info < 24 {
        // Short form: length encoded in header
        (additional_info as usize, 1)
    } else if additional_info == 24 {
        // 1-byte length follows
        if cbor.len() < 2 {
            return Err(CborError::BufferTooSmall);
        }
        (cbor[1] as usize, 2)
    } else if additional_info == 25 {
        // 2-byte length follows
        if cbor.len() < 3 {
            return Err(CborError::BufferTooSmall);
        }
        let len = u16::from_be_bytes([cbor[1], cbor[2]]) as usize;
        (len, 3)
    } else if additional_info == 26 {
        // 4-byte length follows
        if cbor.len() < 5 {
            return Err(CborError::BufferTooSmall);
        }
        let len = u32::from_be_bytes([cbor[1], cbor[2], cbor[3], cbor[4]]) as usize;
        (len, 5)
    } else {
        return Err(CborError::InvalidEncoding);
    };

    // Check if we have enough bytes
    if cbor.len() < offset + length {
        return Err(CborError::BufferTooSmall);
    }

    // Extract the byte string
    Ok(cbor[offset..offset + length].to_vec())
}

/// Encode verification key to CBOR format
///
/// Wraps the raw serialized verification key in CBOR byte string encoding.
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_verification_key(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode verification key from CBOR format
///
/// Extracts raw bytes from CBOR byte string encoding.
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_verification_key(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

/// Encode signature to CBOR format
///
/// Wraps the raw serialized signature in CBOR byte string encoding.
#[cfg(feature = "alloc")]
#[inline]
pub fn encode_signature(raw_bytes: &[u8]) -> Vec<u8> {
    encode_bytes(raw_bytes)
}

/// Decode signature from CBOR format
///
/// Extracts raw bytes from CBOR byte string encoding.
#[cfg(feature = "alloc")]
#[inline]
pub fn decode_signature(cbor: &[u8]) -> Result<Vec<u8>, CborError> {
    decode_bytes(cbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_encode_decode_short() {
        // Test with short byte string (< 24 bytes)
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = encode_bytes(&data);

        // Should be: header (0x45 = major type 2, length 5) + data
        assert_eq!(encoded[0], 0x45);
        assert_eq!(&encoded[1..], &data[..]);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_encode_decode_medium() {
        // Test with medium byte string (< 256 bytes)
        let data = vec![0xAB; 200];
        let encoded = encode_bytes(&data);

        // Should be: header (0x58) + length byte (200) + data
        assert_eq!(encoded[0], 0x58);
        assert_eq!(encoded[1], 200);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_encode_decode_large() {
        // Test with large byte string (>= 256 bytes)
        let data = vec![0xCD; 500];
        let encoded = encode_bytes(&data);

        // Should be: header (0x59) + 2-byte length (500) + data
        assert_eq!(encoded[0], 0x59);
        assert_eq!(u16::from_be_bytes([encoded[1], encoded[2]]), 500);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_cbor_verification_key_roundtrip() {
        // Simulate a 32-byte Ed25519 verification key
        let vk_bytes = vec![0x12; 32];

        let encoded = encode_verification_key(&vk_bytes);
        let decoded = decode_verification_key(&encoded).unwrap();

        assert_eq!(decoded, vk_bytes);
    }

    #[test]
    fn test_cbor_signature_roundtrip() {
        // Simulate a 64-byte Ed25519 signature
        let sig_bytes = vec![0x34; 64];

        let encoded = encode_signature(&sig_bytes);
        let decoded = decode_signature(&encoded).unwrap();

        assert_eq!(decoded, sig_bytes);
    }

    #[test]
    fn test_cbor_invalid_major_type() {
        // Try to decode a CBOR integer (major type 0) as byte string
        let invalid = vec![0x00]; // Integer 0

        let result = decode_bytes(&invalid);
        assert!(matches!(result, Err(CborError::UnexpectedStructure)));
    }

    #[test]
    fn test_cbor_buffer_too_small() {
        // Header says 1-byte length follows, but buffer is too short
        let invalid = vec![0x58]; // Missing length byte

        let result = decode_bytes(&invalid);
        assert!(matches!(result, Err(CborError::BufferTooSmall)));
    }

    #[test]
    fn test_cbor_empty() {
        let result = decode_bytes(&[]);
        assert!(matches!(result, Err(CborError::InvalidEncoding)));
    }
}
