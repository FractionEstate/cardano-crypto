//! Edwards curve point and scalar operations
//!
//! Provides utilities for working with Ed25519/Curve25519 points and scalars.

#[cfg(feature = "vrf")]
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

use super::error::{CryptoError, CryptoResult};

#[cfg(feature = "vrf")]
/// Decompress bytes into an Edwards curve point
pub fn bytes_to_point(bytes: &[u8; 32]) -> CryptoResult<EdwardsPoint> {
    CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)
}

#[cfg(feature = "vrf")]
/// Compress an Edwards curve point to bytes
#[must_use]
pub fn point_to_bytes(point: &EdwardsPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

#[cfg(feature = "vrf")]
/// Decode bytes as a scalar modulo the group order
#[must_use]
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

#[cfg(feature = "vrf")]
/// Encode a scalar as 32 bytes
#[must_use]
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

#[cfg(feature = "vrf")]
/// Clamp scalar bytes for Ed25519 compatibility
///
/// This applies the standard Ed25519 clamping:
/// - Clear the 3 lowest bits (ensure scalar is divisible by 8)
/// - Clear the highest bit (ensure scalar is less than 2^255)
/// - Set the second-highest bit (ensure scalar is at least 2^254)
#[must_use]
pub fn clamp_scalar(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 248;   // Clear 3 low bits
    bytes[31] &= 127;  // Clear high bit
    bytes[31] |= 64;   // Set second-high bit
    bytes
}

#[cfg(all(test, feature = "vrf"))]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_scalar() {
        let bytes = [0xFFu8; 32];
        let clamped = clamp_scalar(bytes);

        // Check that low 3 bits are cleared
        assert_eq!(clamped[0] & 0b111, 0);

        // Check that high bit is cleared
        assert_eq!(clamped[31] & 0b10000000, 0);

        // Check that second-high bit is set
        assert_eq!(clamped[31] & 0b01000000, 0b01000000);
    }
}
