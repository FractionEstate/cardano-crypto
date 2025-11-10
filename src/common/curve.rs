//! Edwards curve point and scalar operations
//!
//! Provides utilities for working with Ed25519/Curve25519 elliptic curve points and scalars.
//! These operations are fundamental to VRF (Verifiable Random Function) implementations
//! and other elliptic curve cryptography in Cardano.
//!
//! The module uses the `curve25519-dalek` library for the underlying curve arithmetic,
//! providing a high-level interface for common operations needed in cryptographic protocols.

#[cfg(feature = "vrf")]
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

use super::error::{CryptoError, CryptoResult};

#[cfg(feature = "vrf")]
/// Decompress 32 bytes into an Edwards curve point
///
/// Attempts to decompress a compressed Edwards Y coordinate into a full Edwards curve point.
/// This is the inverse operation of `point_to_bytes`.
///
/// # Compression Format
///
/// Edwards curve points on Curve25519 can be compressed to 32 bytes by storing only the
/// Y coordinate and the sign of the X coordinate. This function recovers the full point
/// from this compressed representation.
///
/// # Errors
///
/// Returns `CryptoError::InvalidPoint` if the bytes do not represent a valid curve point.
/// This can happen if:
/// - The Y coordinate is not in the valid range
/// - The point is not on the curve
/// - The compressed representation is malformed
///
/// # Examples
///
/// ```ignore
/// use cardano_crypto::common::curve::{bytes_to_point, point_to_bytes};
///
/// let bytes = [0u8; 32]; // Identity point
/// let point = bytes_to_point(&bytes)?;
/// let recovered = point_to_bytes(&point);
/// assert_eq!(&bytes, &recovered);
/// ```
///
/// # Parameters
///
/// * `bytes` - 32-byte compressed Edwards Y coordinate with sign bit
///
/// # Returns
///
/// The decompressed Edwards curve point, or an error if decompression fails
pub fn bytes_to_point(bytes: &[u8; 32]) -> CryptoResult<EdwardsPoint> {
    CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)
}

#[cfg(feature = "vrf")]
/// Compress an Edwards curve point to 32 bytes
///
/// Compresses an Edwards curve point into its canonical 32-byte representation
/// by encoding the Y coordinate and the sign of the X coordinate.
///
/// # Compression Format
///
/// The compressed format stores:
/// - The Y coordinate (255 bits)
/// - The sign/parity of the X coordinate (1 bit)
///
/// This allows faithful reconstruction of the original point using `bytes_to_point`.
///
/// # Examples
///
/// ```ignore
/// use cardano_crypto::common::curve::{bytes_to_point, point_to_bytes};
/// use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
///
/// let compressed = point_to_bytes(&ED25519_BASEPOINT_POINT);
/// assert_eq!(compressed.len(), 32);
/// ```
///
/// # Parameters
///
/// * `point` - Edwards curve point to compress
///
/// # Returns
///
/// 32-byte compressed representation of the point
#[must_use]
pub fn point_to_bytes(point: &EdwardsPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

#[cfg(feature = "vrf")]
/// Decode 32 bytes as a scalar modulo the group order
///
/// Interprets the provided bytes as a scalar value, automatically reducing it
/// modulo the Ed25519 group order (ℓ = 2^252 + 27742317777372353535851937790883648493).
///
/// # Scalar Reduction
///
/// Unlike `bytes_to_point`, this function never fails because any 32-byte input
/// can be interpreted as an integer and reduced modulo the group order. This makes
/// it suitable for deriving scalars from hash outputs or other sources.
///
/// # Examples
///
/// ```ignore
/// use cardano_crypto::common::curve::{bytes_to_scalar, scalar_to_bytes};
///
/// let bytes = [0xFF; 32]; // Large value
/// let scalar = bytes_to_scalar(&bytes);
/// let encoded = scalar_to_bytes(&scalar);
/// // The encoded value will be reduced modulo the group order
/// ```
///
/// # Parameters
///
/// * `bytes` - 32-byte value to interpret as a scalar
///
/// # Returns
///
/// Scalar value in the range [0, ℓ) where ℓ is the Ed25519 group order
#[must_use]
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

#[cfg(feature = "vrf")]
/// Encode a scalar as 32 bytes in little-endian format
///
/// Serializes a scalar value to its canonical 32-byte little-endian representation.
/// This is the inverse operation of `bytes_to_scalar`.
///
/// # Encoding Format
///
/// The scalar is encoded in little-endian byte order (least significant byte first),
/// which is the standard format for Ed25519 and Curve25519.
///
/// # Examples
///
/// ```ignore
/// use cardano_crypto::common::curve::{bytes_to_scalar, scalar_to_bytes};
/// use curve25519_dalek::scalar::Scalar;
///
/// let original = Scalar::ONE;
/// let bytes = scalar_to_bytes(&original);
/// let recovered = bytes_to_scalar(&bytes);
/// assert_eq!(original, recovered);
/// ```
///
/// # Parameters
///
/// * `scalar` - Scalar value to encode
///
/// # Returns
///
/// 32-byte little-endian representation of the scalar
#[must_use]
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

#[cfg(feature = "vrf")]
/// Clamp scalar bytes for Ed25519 compatibility
///
/// Applies the standard Ed25519 scalar clamping operation to ensure the resulting
/// value is suitable for use as a private key in Ed25519 signatures and key agreement.
///
/// # Clamping Rules
///
/// The clamping operation modifies the scalar bytes as follows:
/// 1. Clear the 3 lowest bits (bits 0, 1, 2): Ensures divisibility by 8 (cofactor)
/// 2. Clear the highest bit (bit 255): Ensures the value is less than 2^255
/// 3. Set the second-highest bit (bit 254): Ensures the value is at least 2^254
///
/// # Purpose
///
/// Clamping serves multiple security purposes:
/// - Ensures the scalar avoids small subgroup attacks
/// - Guarantees the scalar is in a safe range
/// - Makes timing attacks more difficult
/// - Ensures compatibility with the Ed25519 specification (RFC 8032)
///
/// # Examples
///
/// ```
/// use cardano_crypto::common::curve::clamp_scalar;
///
/// let unclamped = [0xFF; 32];
/// let clamped = clamp_scalar(unclamped);
///
/// // Verify clamping properties
/// assert_eq!(clamped[0] & 0b111, 0);        // Low 3 bits cleared
/// assert_eq!(clamped[31] & 0b10000000, 0);  // Highest bit cleared
/// assert_eq!(clamped[31] & 0b01000000, 64); // Second-highest bit set
/// ```
///
/// # Parameters
///
/// * `bytes` - Unclamped 32-byte scalar value
///
/// # Returns
///
/// Clamped 32-byte scalar suitable for Ed25519 operations
#[must_use]
pub fn clamp_scalar(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 248; // Clear 3 low bits
    bytes[31] &= 127; // Clear high bit
    bytes[31] |= 64; // Set second-high bit
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
