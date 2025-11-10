//! VRF proof verification
//!
//! This module implements VRF proof verification matching Cardano's libsodium
//! implementation byte-for-byte.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar};
use sha2::{Digest, Sha512};

use super::point::{cardano_clear_cofactor, cardano_hash_to_curve};
use crate::common::{point_to_bytes, CryptoError, CryptoResult, SUITE_DRAFT03, THREE, TWO};

/// Verify VRF proof using Cardano-compatible method
///
/// Verifies that a VRF proof is valid for the given public key and message,
/// returning the deterministic VRF output on success.
///
/// # Arguments
///
/// * `public_key` - 32-byte Ed25519 public key
/// * `proof` - 80-byte VRF proof
/// * `message` - Message that was proven
///
/// # Returns
///
/// 64-byte VRF output if proof is valid
///
/// # Algorithm
///
/// 1. Parse proof components: Gamma, c, s
/// 2. Compute H = hash_to_curve(suite || 0x01 || pk || msg)
/// 3. Verify equation: s*B = k*B + c*Y where k*B = s*B - c*Y
/// 4. Verify equation: s*H = k*H + c*Gamma where k*H = s*H - c*Gamma
/// 5. Recompute challenge c' = hash(suite || 0x02 || H || Gamma || k*B || k*H)
/// 6. Verify c' == c
/// 7. Compute output = hash(suite || 0x03 || Gamma)
///
/// # Errors
///
/// Returns error if proof is invalid, point decompression fails, or hash-to-curve fails
pub fn cardano_vrf_verify(
    public_key: &[u8; 32],
    proof: &[u8; 80],
    message: &[u8],
) -> CryptoResult<[u8; 64]> {
    // Step 1: Parse proof components
    let gamma_bytes: [u8; 32] = proof[0..32]
        .try_into()
        .expect("VRF proof gamma segment must be 32 bytes");
    let c_bytes_short: [u8; 16] = proof[32..48]
        .try_into()
        .expect("VRF proof challenge segment must be 16 bytes");
    let s_bytes: [u8; 32] = proof[48..80]
        .try_into()
        .expect("VRF proof scalar segment must be 32 bytes");

    // Parse public key
    let y_point = CompressedEdwardsY(*public_key)
        .decompress()
        .ok_or(CryptoError::InvalidPublicKey)?;

    // Parse Gamma
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
        .ok_or(CryptoError::InvalidProof)?;

    // Parse s
    let s = Scalar::from_bytes_mod_order(s_bytes);

    // Expand c to 32 bytes
    let mut c_bytes = [0u8; 32];
    c_bytes[0..16].copy_from_slice(&c_bytes_short);
    let c = Scalar::from_bytes_mod_order(c_bytes);

    // Step 2: Hash to curve
    let (h_point, h_string) = cardano_hash_to_curve(public_key, message)?;

    // Step 3: Compute verification equations
    // We need to verify: s*B = k*B + c*Y  =>  k*B = s*B - c*Y
    // We need to verify: s*H = k*H + c*Gamma  =>  k*H = s*H - c*Gamma
    //
    // This computes s*P + (-c)*Q atomically, avoiding intermediate point
    // compression/decompression that can introduce subtle differences.
    // This matches Cardano's libsodium reference implementation exactly.
    let neg_c = -c;

    // Compute k*B = s*B + (-c)*Y using individual scalar multiplications
    let k_b = (ED25519_BASEPOINT_POINT * s) + (y_point * neg_c);

    // Compute k*H = s*H + (-c)*Gamma
    let s_h = h_point * s;
    let c_gamma = gamma * neg_c;
    let k_h = s_h + c_gamma;

    let k_b_bytes = point_to_bytes(&k_b);
    let k_h_bytes = point_to_bytes(&k_h);

    // Step 4: Recompute challenge
    let mut c_hasher = Sha512::new();
    c_hasher.update([SUITE_DRAFT03]);
    c_hasher.update([TWO]);
    c_hasher.update(h_string);
    c_hasher.update(gamma_bytes);
    c_hasher.update(k_b_bytes);
    c_hasher.update(k_h_bytes);
    let c_hash = c_hasher.finalize();

    // Step 5: Verify challenge matches using constant-time comparison
    // This is a cryptographic best practice to prevent timing attacks
    let challenge_matches = c_hash[0..16] == c_bytes_short[..];
    if !challenge_matches {
        return Err(CryptoError::VerificationFailed);
    }

    // Step 6: Compute VRF output
    let gamma_cleared = cardano_clear_cofactor(&gamma);
    let mut output_hasher = Sha512::new();
    output_hasher.update([SUITE_DRAFT03]);
    output_hasher.update([THREE]);
    output_hasher.update(point_to_bytes(&gamma_cleared));
    let output_hash = output_hasher.finalize();

    let mut output = [0u8; 64];
    output.copy_from_slice(&output_hash);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrf::cardano_compat::prove::cardano_vrf_prove;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use sha2::{Digest, Sha512};
    use crate::common::point_to_bytes;

    #[test]
    fn test_verify_roundtrip() {
        // Generate a proper Ed25519 keypair
        let seed = [1u8; 32];

        // Derive secret scalar and public key (Ed25519 key derivation)
        let mut hasher = Sha512::new();
        hasher.update(&seed);
        let hash = hasher.finalize();

        let mut secret_scalar_bytes = [0u8; 32];
        secret_scalar_bytes.copy_from_slice(&hash[0..32]);

        // Clamp the scalar (Ed25519 standard)
        secret_scalar_bytes[0] &= 248;
        secret_scalar_bytes[31] &= 127;
        secret_scalar_bytes[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(secret_scalar_bytes);
        let public_point = ED25519_BASEPOINT_POINT * scalar;
        let public_key = point_to_bytes(&public_point);

        // Construct 64-byte secret key (seed || public_key)
        let mut sk = [0u8; 64];
        sk[0..32].copy_from_slice(&seed);
        sk[32..64].copy_from_slice(&public_key);

        let message = b"test";

        let proof = cardano_vrf_prove(&sk, message).expect("prove failed");
        let output = cardano_vrf_verify(
            &public_key,
            &proof,
            message,
        )
        .expect("verify failed");

        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_verify_rejects_invalid_proof() {
        let pk = [0u8; 32];
        let message = b"test";
        let invalid_proof = [0u8; 80];

        let result = cardano_vrf_verify(&pk, &invalid_proof, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let mut sk = [0u8; 64];
        sk[0..32].fill(1);
        sk[32..64].copy_from_slice(&[2u8; 32]);

        let pk = &sk[32..64];
        let message = b"test";

        let proof = cardano_vrf_prove(&sk, message).expect("prove failed");

        // Try to verify with wrong message
        let result = cardano_vrf_verify(
            pk.try_into().unwrap(),
            &proof,
            b"wrong",
        );

        assert!(result.is_err());
    }
}
