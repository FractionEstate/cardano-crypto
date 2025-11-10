//! VRF proof generation
//!
//! This module implements VRF proof generation matching Cardano's libsodium
//! implementation byte-for-byte.
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::vrf::cardano_compat::cardano_vrf_prove;
//!
//! // Proof generation requires a valid 64-byte Ed25519 extended secret key
//! // This is typically derived from a seed using proper Ed25519 key generation
//! let secret_key = [1u8; 64]; // Simplified for example
//! let message = b"block data";
//!
//! // Generate VRF proof - returns 80 bytes
//! let result = cardano_vrf_prove(&secret_key, message);
//! // Note: Result type demonstrates API; actual generation requires valid keys
//! # let _ = result; // Suppress unused warning
//! ```

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::point::cardano_hash_to_curve;
use crate::common::{point_to_bytes, CryptoResult, SUITE_DRAFT03, TWO};

/// Generate VRF proof using Cardano-compatible method
///
/// Produces a VRF proof that matches libsodium's output byte-for-byte.
///
/// # Arguments
///
/// * `secret_key` - 64-byte secret key (32-byte seed + 32-byte public key)
/// * `message` - Message to generate proof for
///
/// # Returns
///
/// 80-byte VRF proof consisting of:
/// - 32 bytes: Gamma (VRF output point)
/// - 16 bytes: Challenge c
/// - 32 bytes: Scalar s
///
/// # Example
///
/// ```rust
/// use cardano_crypto::vrf::cardano_compat::cardano_vrf_prove;
///
/// // VRF proof generation (requires valid Ed25519 extended secret key)
/// let secret_key = [42u8; 64]; // In practice, derive from proper keygen
/// let message = b"Cardano slot leader selection";
///
/// // Generate proof - returns Result with 80-byte proof
/// let result = cardano_vrf_prove(&secret_key, message);
/// // Actual cryptographic operations require valid keys
/// # let _ = result;
/// ```
pub fn cardano_vrf_prove(secret_key: &[u8; 64], message: &[u8]) -> CryptoResult<[u8; 80]> {
    // Step 1: Expand secret key
    let mut az = Zeroizing::new([0u8; 64]);
    let mut hasher = Sha512::new();
    hasher.update(&secret_key[0..32]);
    let hash = hasher.finalize();
    az.copy_from_slice(&hash);

    // Step 2: Clamp scalar (same as Ed25519)
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;

    let secret_scalar_bytes: [u8; 32] = az[0..32]
        .try_into()
        .expect("secret key slice must be 32 bytes");
    let x = Scalar::from_bytes_mod_order(secret_scalar_bytes);

    // Extract public key
    let pk = &secret_key[32..64];

    // Step 3: Hash to curve H = hash_to_curve(suite || 0x01 || pk || message)
    let (h_point, h_string) = cardano_hash_to_curve(pk, message)?;

    // Step 4: Compute Gamma = x * H
    let gamma = h_point * x;
    let gamma_bytes = point_to_bytes(&gamma);

    // Step 5: Compute nonce k = SHA512(az[32..64] || h_string)
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

    // Step 7: Compute challenge c = SHA512(suite || 0x02 || H || Gamma || k*B || k*H)[0..16]
    let mut c_hasher = Sha512::new();
    c_hasher.update([SUITE_DRAFT03]);
    c_hasher.update([TWO]);
    c_hasher.update(h_string);
    c_hasher.update(gamma_bytes);
    c_hasher.update(k_b_bytes);
    c_hasher.update(k_h_bytes);
    let c_hash = c_hasher.finalize();
    let c_bytes_short: [u8; 16] = c_hash[0..16].try_into().unwrap();

    // Expand c to 32 bytes for scalar operations
    let mut c_bytes = [0u8; 32];
    c_bytes[0..16].copy_from_slice(&c_bytes_short);
    let c = Scalar::from_bytes_mod_order(c_bytes);

    // Step 8: Compute s = k + c*x mod L
    let s = k + (c * x);
    let s_bytes = s.to_bytes();

    // Step 9: Construct proof (80 bytes)
    let mut proof = [0u8; 80];
    proof[0..32].copy_from_slice(&gamma_bytes);
    proof[32..48].copy_from_slice(&c_bytes_short);
    proof[48..80].copy_from_slice(&s_bytes);

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_deterministic() {
        let mut sk = [0u8; 64];
        sk[0..32].fill(1);
        sk[32..64].copy_from_slice(&[2u8; 32]);

        let message = b"test";

        let proof1 = cardano_vrf_prove(&sk, message).expect("prove failed");
        let proof2 = cardano_vrf_prove(&sk, message).expect("prove failed");

        assert_eq!(proof1, proof2);
    }
}
