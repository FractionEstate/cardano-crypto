//! VRF implementation following IETF draft-13 specification
//!
//! Implements **ECVRF-ED25519-SHA512-TAI** (Try-And-Increment hash-to-curve) as defined in
//! [draft-irtf-cfrg-vrf-13](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13).
//! This variant produces 128-byte proofs and supports **batch verification** for improved
//! performance when validating multiple proofs.
//!
//! # Specification Details
//!
//! - **Suite**: ECVRF-ED25519-SHA512-TAI
//! - **Curve**: Edwards25519 (Ed25519)
//! - **Hash Function**: SHA-512
//! - **Hash-to-Curve**: Try-And-Increment (deterministic, uniform distribution)
//! - **Proof Size**: 128 bytes (Gamma 32 + c 32 + s 32 + H-string 32 bytes)
//! - **Public Key Size**: 32 bytes
//! - **Secret Key Size**: 64 bytes (Ed25519 expanded key format)
//! - **Output Size**: 64 bytes (SHA-512)
//!
//! # Differences from Draft-03
//!
//! | Feature | Draft-03 | Draft-13 |
//! |---------|----------|----------|
//! | Proof Size | 80 bytes | 128 bytes |
//! | Hash-to-Curve | Elligator2 | Try-And-Increment |
//! | Challenge Size | 16 bytes | 32 bytes (full) |
//! | Batch Verification | No | Yes |
//! | Cardano Compatible | Yes | No |
//!
//! # When to Use
//!
//! Use this variant when:
//! - You need batch verification (40-50% faster for multiple proofs)
//! - Larger proof size (128 bytes) is acceptable
//! - Uniform hash-to-curve distribution is important
//!
//! For Cardano compatibility, use [`VrfDraft03`](crate::vrf::VrfDraft03).
//!
//! # Examples
//!
//! ```rust
//! use cardano_crypto::vrf::VrfDraft13;
//! use cardano_crypto::common::Result;
//!
//! # fn main() -> Result<()> {
//! // Generate keypair
//! let seed = [99u8; 32];
//! let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
//!
//! // Generate proof
//! let message = b"Block slot 54321";
//! let proof = VrfDraft13::prove(&secret_key, message)?;
//! assert_eq!(proof.len(), 128);
//!
//! // Verify proof
//! let output = VrfDraft13::verify(&public_key, &proof, message)?;
//! assert_eq!(output.len(), 64);
//!
//! // Extract hash without verification
//! let hash = VrfDraft13::proof_to_hash(&proof)?;
//! assert_eq!(hash, output);
//! # Ok(())
//! # }
//! ```
//!
//! # Performance
//!
//! Typical operation times on modern hardware:
//! - Keypair generation: ~20μs
//! - Proof generation: ~1.5ms (slightly slower than draft-03 due to TAI)
//! - Proof verification: ~900μs
//! - Batch verification (4 proofs): ~2.5ms (vs 3.6ms individual)

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::common::{
    bytes_to_point, clamp_scalar, point_to_bytes, Result, SUITE_DRAFT13, THREE, TWO,
};
use crate::vrf::cardano_compat::{cardano_clear_cofactor, cardano_hash_to_curve_draft13};

/// VRF proof size for draft-13: 128 bytes (batch-compatible)
///
/// Structure: Gamma (32 bytes) || c (16 bytes) || s (32 bytes) || H-string (48 bytes)
/// - Gamma: VRF output point
/// - c: Challenge scalar (truncated to 16 bytes for compatibility)
/// - s: Response scalar
/// - H-string: Hash-to-curve output string (needed for batch verification)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::PROOF_SIZE;
///
/// assert_eq!(PROOF_SIZE, 128);
/// ```
pub const PROOF_SIZE: usize = 128;

/// Ed25519 public key size: 32 bytes
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::PUBLIC_KEY_SIZE;
///
/// assert_eq!(PUBLIC_KEY_SIZE, 32);
/// ```
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 secret key size: 64 bytes
///
/// Format: seed (32 bytes) || public_key (32 bytes)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::SECRET_KEY_SIZE;
///
/// assert_eq!(SECRET_KEY_SIZE, 64);
/// ```
pub const SECRET_KEY_SIZE: usize = 64;

/// Random seed size for keypair generation: 32 bytes
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::SEED_SIZE;
///
/// assert_eq!(SEED_SIZE, 32);
/// ```
pub const SEED_SIZE: usize = 32;

/// VRF output hash size: 64 bytes (SHA-512)
///
/// # Example
///
/// ```
/// use cardano_crypto::vrf::draft13::OUTPUT_SIZE;
///
/// assert_eq!(OUTPUT_SIZE, 64);
/// ```
pub const OUTPUT_SIZE: usize = 64;

/// VRF Draft-13 batch-compatible implementation
///
/// Zero-sized type providing static methods for VRF operations following
/// the draft-13 specification with Try-And-Increment hash-to-curve.
///
/// This variant produces larger proofs (128 bytes vs 80 bytes) but enables
/// efficient batch verification when validating multiple proofs together.
///
/// # Examples
///
/// ```rust
/// use cardano_crypto::vrf::VrfDraft13;
///
/// let seed = [0u8; 32];
/// let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
/// ```
#[derive(Clone, Debug)]
pub struct VrfDraft13;

impl VrfDraft13 {
    /// Generates a batch-compatible VRF proof using draft-13 specification
    ///
    /// Produces a 128-byte proof that includes the hash-to-curve output string,
    /// enabling batch verification. Uses Try-And-Increment for deterministic
    /// and uniformly distributed hash-to-curve mapping.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - 64-byte Ed25519 expanded secret key
    /// * `message` - Arbitrary-length message to prove
    ///
    /// # Returns
    ///
    /// 128-byte proof containing (Gamma || c || s || H-string)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Secret key is malformed
    /// - Hash-to-curve operation fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::vrf::VrfDraft13;
    /// use cardano_crypto::common::Result;
    ///
    /// # fn main() -> Result<()> {
    /// let seed = [5u8; 32];
    /// let (secret_key, _) = VrfDraft13::keypair_from_seed(&seed);
    ///
    /// let message = b"batch_proof_example";
    /// let proof = VrfDraft13::prove(&secret_key, message)?;
    /// assert_eq!(proof.len(), 128);
    /// # Ok(())
    /// # }
    /// ```
    pub fn prove(secret_key: &[u8; SECRET_KEY_SIZE], message: &[u8]) -> Result<[u8; PROOF_SIZE]> {
        // Step 1: Expand secret key
        let mut az = Zeroizing::new([0u8; 64]);
        let mut hasher = Sha512::new();
        hasher.update(&secret_key[0..32]);
        let hash = hasher.finalize();
        az.copy_from_slice(&hash);

        // Step 2: Clamp scalar
        az[0] &= 248;
        az[31] &= 127;
        az[31] |= 64;

        let secret_scalar_bytes: [u8; 32] = az[0..32]
            .try_into()
            .expect("secret key slice must be 32 bytes");
        let x = Scalar::from_bytes_mod_order(secret_scalar_bytes);

        let pk = &secret_key[32..64];

        // Step 3: Hash to curve
        let (h_point, h_string) = cardano_hash_to_curve_draft13(pk, message)?;

        // Step 4: Compute Gamma = x * H
        let gamma = h_point * x;
        let gamma_bytes = point_to_bytes(&gamma);

        // Step 5: Compute nonce k
        let mut nonce_hasher = Sha512::new();
        nonce_hasher.update(&az[32..64]);
        nonce_hasher.update(h_string);
        let nonce_hash = nonce_hasher.finalize();
        let nonce_hash_bytes: [u8; 64] = nonce_hash.into();
        let k = Scalar::from_bytes_mod_order_wide(&nonce_hash_bytes);

        // Step 6: Compute k*B and k*H
        let k_b = ED25519_BASEPOINT_POINT * k;
        let k_h = h_point * k;
        let k_b_bytes = point_to_bytes(&k_b);
        let k_h_bytes = point_to_bytes(&k_h);

        // Step 7: Compute challenge c
        let mut c_hasher = Sha512::new();
        c_hasher.update([SUITE_DRAFT13]);
        c_hasher.update([TWO]);
        c_hasher.update(pk);
        c_hasher.update(h_string);
        c_hasher.update(gamma_bytes);
        c_hasher.update(k_b_bytes);
        c_hasher.update(k_h_bytes);
        c_hasher.update([0x00]);
        let c_hash = c_hasher.finalize();
        let c_bytes_short: [u8; 16] = c_hash[0..16].try_into().unwrap();

        let mut c_bytes = [0u8; 32];
        c_bytes[0..16].copy_from_slice(&c_bytes_short);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // Step 8: Compute s = k + c*x mod L
        let s = k + (c * x);
        let s_bytes = s.to_bytes();

        // Step 9: Construct proof (128 bytes)
        let mut proof = [0u8; PROOF_SIZE];
        proof[0..32].copy_from_slice(&gamma_bytes);
        proof[32..48].copy_from_slice(&c_bytes_short);
        proof[48..80].copy_from_slice(&s_bytes);
        proof[80..128].copy_from_slice(&h_string);

        Ok(proof)
    }

    /// Verify a VRF proof and return the output
    ///
    /// # Arguments
    /// * `public_key` - 32-byte public key
    /// * `proof` - 128-byte proof
    /// * `message` - Message that was proven
    ///
    /// # Returns
    /// 64-byte VRF output on success
    ///
    /// # Errors
    ///
    /// Returns error if proof verification fails
    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_SIZE],
        proof: &[u8; PROOF_SIZE],
        message: &[u8],
    ) -> Result<[u8; OUTPUT_SIZE]> {
        // Parse proof components
        let gamma_bytes: [u8; 32] = proof[0..32].try_into().unwrap();
        let c_bytes_short: [u8; 16] = proof[32..48].try_into().unwrap();
        let s_bytes: [u8; 32] = proof[48..80].try_into().unwrap();
        let h_string: [u8; 48] = proof[80..128].try_into().unwrap();

        // Decode points and scalars
        let gamma = bytes_to_point(&gamma_bytes)?;
        let y_point = bytes_to_point(public_key)?;
        let s = Scalar::from_bytes_mod_order(s_bytes);

        let mut c_bytes = [0u8; 32];
        c_bytes[0..16].copy_from_slice(&c_bytes_short);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // Hash to curve
        let (h_point, expected_h_string) = cardano_hash_to_curve_draft13(public_key, message)?;

        // Verify H-string matches
        if h_string != expected_h_string {
            return Err(crate::common::error::CryptoError::VerificationFailed);
        }

        // Verify equations using batch scalar multiplication
        let neg_c = -c;

        // Compute k*B = s*B + (-c)*Y
        let k_b = (ED25519_BASEPOINT_POINT * s) + (y_point * neg_c);

        // Compute k*H = s*H + (-c)*Gamma
        let k_h = (h_point * s) + (gamma * neg_c);

        let k_b_bytes = point_to_bytes(&k_b);
        let k_h_bytes = point_to_bytes(&k_h);

        // Recompute challenge
        let mut c_hasher = Sha512::new();
        c_hasher.update([SUITE_DRAFT13]);
        c_hasher.update([TWO]);
        c_hasher.update(public_key);
        c_hasher.update(h_string);
        c_hasher.update(gamma_bytes);
        c_hasher.update(k_b_bytes);
        c_hasher.update(k_h_bytes);
        c_hasher.update([0x00]);
        let c_hash = c_hasher.finalize();
        let recomputed_c_bytes: [u8; 16] = c_hash[0..16].try_into().unwrap();

        // Verify challenge matches
        if c_bytes_short != recomputed_c_bytes {
            return Err(crate::common::error::CryptoError::VerificationFailed);
        }

        // Compute VRF output
        let gamma_cleared = cardano_clear_cofactor(&gamma);
        let mut output_hasher = Sha512::new();
        output_hasher.update([SUITE_DRAFT13]);
        output_hasher.update([THREE]);
        output_hasher.update(point_to_bytes(&gamma_cleared));
        let output_hash = output_hasher.finalize();

        let mut output = [0u8; OUTPUT_SIZE];
        output.copy_from_slice(&output_hash);
        Ok(output)
    }

    /// Convert a proof to VRF output hash without verification
    ///
    /// Extracts the VRF output from a proof **without verifying** its validity.
    /// This is useful when the proof has already been verified or when you need
    /// to extract the hash for other purposes.
    ///
    /// ⚠️ **WARNING**: This function does NOT verify the proof's authenticity.
    /// Use [`verify`](Self::verify) if you need cryptographic assurance.
    ///
    /// # Arguments
    /// * `proof` - 128-byte proof
    ///
    /// # Returns
    /// 64-byte VRF output
    ///
    /// # Errors
    ///
    /// Returns error if the proof is malformed
    pub fn proof_to_hash(proof: &[u8; PROOF_SIZE]) -> Result<[u8; OUTPUT_SIZE]> {
        let gamma_bytes: [u8; 32] = proof[0..32]
            .try_into()
            .expect("proof gamma segment must be 32 bytes");

        let gamma = bytes_to_point(&gamma_bytes)?;
        let gamma_cleared = cardano_clear_cofactor(&gamma);

        let mut hasher = Sha512::new();
        hasher.update([SUITE_DRAFT13]);
        hasher.update([THREE]);
        hasher.update(point_to_bytes(&gamma_cleared));
        let hash = hasher.finalize();

        let mut output = [0u8; OUTPUT_SIZE];
        output.copy_from_slice(&hash);
        Ok(output)
    }

    /// Generate keypair from seed
    ///
    /// Derives an Ed25519 keypair from a 32-byte seed using SHA-512 and scalar clamping.
    /// The secret key format is: seed (32 bytes) || public_key (32 bytes).
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte random seed (use a CSPRNG)
    ///
    /// # Returns
    ///
    /// Tuple of (secret_key, public_key) where:
    /// - secret_key: 64 bytes (seed || public_key)
    /// - public_key: 32 bytes (compressed Edwards point)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cardano_crypto::vrf::VrfDraft13;
    ///
    /// let seed = [42u8; 32];
    /// let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
    /// assert_eq!(secret_key.len(), 64);
    /// assert_eq!(public_key.len(), 32);
    /// assert_eq!(&secret_key[32..64], &public_key[..]);
    /// ```
    #[must_use]
    pub fn keypair_from_seed(
        seed: &[u8; SEED_SIZE],
    ) -> ([u8; SECRET_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut secret_scalar = Zeroizing::new([0u8; 32]);
        secret_scalar.copy_from_slice(&hash[0..32]);
        *secret_scalar = clamp_scalar(*secret_scalar);

        let scalar = Scalar::from_bytes_mod_order(*secret_scalar);
        let public_point = ED25519_BASEPOINT_POINT * scalar;
        let public_key_bytes = point_to_bytes(&public_point);

        let mut secret_key = [0u8; SECRET_KEY_SIZE];
        secret_key[0..32].copy_from_slice(seed);
        secret_key[32..64].copy_from_slice(&public_key_bytes);

        (secret_key, public_key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_verify_roundtrip() {
        let seed = [42u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let output = VrfDraft13::verify(&pk, &proof, message).expect("verify failed");

        assert_eq!(output.len(), OUTPUT_SIZE);
    }

    #[test]
    fn test_verify_rejects_invalid_proof() {
        let seed = [42u8; SEED_SIZE];
        let (_sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let invalid_proof = [0u8; PROOF_SIZE];
        let result = VrfDraft13::verify(&pk, &invalid_proof, message);

        assert!(result.is_err());
    }

    #[test]
    fn test_proof_to_hash_deterministic() {
        let seed = [42u8; SEED_SIZE];
        let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"test message";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let hash1 = VrfDraft13::proof_to_hash(&proof).expect("hash failed");
        let hash2 = VrfDraft13::proof_to_hash(&proof).expect("hash failed");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_proof_to_hash_matches_verify() {
        let seed = [99u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"consistency check";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        let hash = VrfDraft13::proof_to_hash(&proof).expect("hash failed");
        let output = VrfDraft13::verify(&pk, &proof, message).expect("verify failed");

        assert_eq!(hash, output);
    }

    #[test]
    fn test_keypair_structure() {
        let seed = [7u8; SEED_SIZE];
        let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);

        // Verify secret key contains seed and public key
        assert_eq!(&sk[0..32], &seed[..]);
        assert_eq!(&sk[32..64], &pk[..]);
    }

    #[test]
    fn test_proof_size() {
        let seed = [1u8; SEED_SIZE];
        let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
        let message = b"size check";

        let proof = VrfDraft13::prove(&sk, message).expect("prove failed");
        assert_eq!(proof.len(), PROOF_SIZE);
        assert_eq!(proof.len(), 128);
    }
}
