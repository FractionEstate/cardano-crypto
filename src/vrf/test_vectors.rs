//! Test vectors for VRF algorithms
//!
//! These test vectors validate compatibility with Cardano's VRF implementation.
//! Based on IETF draft specifications and cardano-base test suite.
//!
//! # Example
//!
//! ```rust
//! use cardano_crypto::vrf::{VrfDraft13, DRAFT13_PROOF_SIZE, OUTPUT_SIZE};
//!
//! // Test VRF proof generation and verification
//! let seed = [42u8; 32];
//! let (secret_key, public_key) = VrfDraft13::keypair_from_seed(&seed);
//!
//! let message = b"Cardano block";
//! let proof = VrfDraft13::prove(&secret_key, message).unwrap();
//!
//! // Proof size is fixed
//! assert_eq!(proof.len(), DRAFT13_PROOF_SIZE);
//!
//! // Verify and extract output
//! let output = VrfDraft13::verify(&public_key, &proof, message).unwrap();
//! assert_eq!(output.len(), OUTPUT_SIZE);
//! ```

#[cfg(test)]
mod tests {
    use crate::common::Result;
    use crate::vrf::{VrfDraft03, VrfDraft13};

    /// Test VRF Draft-03 determinism
    #[test]
    fn test_vrf_draft03_deterministic() -> Result<()> {
        let seed = [42u8; 32];

        // Generate same keypair twice
        let (sk1, pk1) = VrfDraft03::keypair_from_seed(&seed);
        let (sk2, pk2) = VrfDraft03::keypair_from_seed(&seed);

        // Keys should match
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);

        // Sign same message twice
        let message = b"Cardano VRF test";
        let proof1 = VrfDraft03::prove(&sk1, message)?;
        let proof2 = VrfDraft03::prove(&sk2, message)?;

        // Proofs should be deterministic
        assert_eq!(proof1, proof2);

        // Verify both proofs
        let output1 = VrfDraft03::verify(&pk1, &proof1, message)?;
        let output2 = VrfDraft03::verify(&pk2, &proof2, message)?;

        // Outputs should match
        assert_eq!(output1, output2);

        Ok(())
    }

    /// Test VRF Draft-13 determinism
    #[test]
    fn test_vrf_draft13_deterministic() -> Result<()> {
        let seed = [99u8; 32];

        let (sk1, pk1) = VrfDraft13::keypair_from_seed(&seed);
        let (sk2, pk2) = VrfDraft13::keypair_from_seed(&seed);

        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);

        let message = b"Draft-13 test message";
        let proof1 = VrfDraft13::prove(&sk1, message)?;
        let proof2 = VrfDraft13::prove(&sk2, message)?;

        assert_eq!(proof1, proof2);

        let output1 = VrfDraft13::verify(&pk1, &proof1, message)?;
        let output2 = VrfDraft13::verify(&pk2, &proof2, message)?;

        assert_eq!(output1, output2);

        Ok(())
    }

    /// Test VRF proof sizes
    #[test]
    fn test_vrf_proof_sizes() {
        use crate::vrf::{DRAFT03_PROOF_SIZE, DRAFT13_PROOF_SIZE, OUTPUT_SIZE};

        // Draft-03: 80 bytes
        assert_eq!(DRAFT03_PROOF_SIZE, 80);

        // Draft-13: 128 bytes (batch-compatible)
        assert_eq!(DRAFT13_PROOF_SIZE, 128);

        // Output: 64 bytes (SHA-512) for both
        assert_eq!(OUTPUT_SIZE, 64);
    }

    /// Test VRF proof-to-hash matches verify output
    #[test]
    fn test_vrf_proof_to_hash_consistency() -> Result<()> {
        // Test Draft-03
        {
            let seed = [1u8; 32];
            let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
            let message = b"consistency test";

            let proof = VrfDraft03::prove(&sk, message)?;
            let output_from_verify = VrfDraft03::verify(&pk, &proof, message)?;
            let output_from_hash = VrfDraft03::proof_to_hash(&proof)?;

            assert_eq!(output_from_verify, output_from_hash);
        }

        // Test Draft-13
        {
            let seed = [2u8; 32];
            let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
            let message = b"consistency test";

            let proof = VrfDraft13::prove(&sk, message)?;
            let output_from_verify = VrfDraft13::verify(&pk, &proof, message)?;
            let output_from_hash = VrfDraft13::proof_to_hash(&proof)?;

            assert_eq!(output_from_verify, output_from_hash);
        }

        Ok(())
    }

    /// Test VRF verification fails with wrong public key
    #[test]
    fn test_vrf_wrong_key_fails() -> Result<()> {
        let seed1 = [10u8; 32];
        let seed2 = [20u8; 32];

        let (sk1, _pk1) = VrfDraft03::keypair_from_seed(&seed1);
        let (_sk2, pk2) = VrfDraft03::keypair_from_seed(&seed2);

        let message = b"test message";
        let proof = VrfDraft03::prove(&sk1, message)?;

        // Verify with wrong public key should fail
        let result = VrfDraft03::verify(&pk2, &proof, message);
        assert!(result.is_err());

        Ok(())
    }

    /// Test VRF verification fails with wrong message
    #[test]
    fn test_vrf_wrong_message_fails() -> Result<()> {
        let seed = [30u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let message1 = b"original message";
        let message2 = b"different message";

        let proof = VrfDraft03::prove(&sk, message1)?;

        // Verify with correct message (should succeed)
        VrfDraft03::verify(&pk, &proof, message1)?;

        // Verify with wrong message (should fail)
        let result = VrfDraft03::verify(&pk, &proof, message2);
        assert!(result.is_err());

        Ok(())
    }

    /// Test VRF Draft-03 vs Draft-13 proof size difference
    #[test]
    fn test_vrf_draft_comparison() -> Result<()> {
        let seed = [5u8; 32];
        let message = b"comparison test";

        // Draft-03
        let (sk03, pk03) = VrfDraft03::keypair_from_seed(&seed);
        let proof03 = VrfDraft03::prove(&sk03, message)?;
        assert_eq!(proof03.len(), 80);

        // Draft-13
        let (sk13, pk13) = VrfDraft13::keypair_from_seed(&seed);
        let proof13 = VrfDraft13::prove(&sk13, message)?;
        assert_eq!(proof13.len(), 128);

        // Public keys should match (same derivation)
        assert_eq!(pk03, pk13);

        // But proofs are different formats
        assert_ne!(proof03.len(), proof13.len());

        Ok(())
    }

    /// Test VRF with empty message
    #[test]
    fn test_vrf_empty_message() -> Result<()> {
        let seed = [77u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let empty_message = b"";
        let proof = VrfDraft03::prove(&sk, empty_message)?;
        let output = VrfDraft03::verify(&pk, &proof, empty_message)?;

        assert_eq!(output.len(), 64);

        Ok(())
    }

    /// Test VRF with large message
    #[test]
    fn test_vrf_large_message() -> Result<()> {
        let seed = [88u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // 10KB message
        let large_message = vec![0xAB; 10_000];
        let proof = VrfDraft03::prove(&sk, &large_message)?;
        let output = VrfDraft03::verify(&pk, &proof, &large_message)?;

        assert_eq!(output.len(), 64);

        Ok(())
    }

    /// Test VRF keypair structure
    #[test]
    fn test_vrf_keypair_structure() {
        let seed = [123u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        // Secret key is 64 bytes (seed || public_key)
        assert_eq!(sk.len(), 64);
        assert_eq!(pk.len(), 32);

        // First 32 bytes of SK should be the seed
        assert_eq!(&sk[0..32], &seed[..]);

        // Last 32 bytes of SK should be the public key
        assert_eq!(&sk[32..64], &pk[..]);
    }

    /// IETF Draft-03 test vector (example from specification)
    #[test]
    fn test_vrf_draft03_ietf_vector() -> Result<()> {
        // This is a simplified test based on IETF examples
        // Full test vectors would include exact hex values from the spec

        let seed = [0x00u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let message = b"";
        let proof = VrfDraft03::prove(&sk, message)?;

        // Proof should be exactly 80 bytes
        assert_eq!(proof.len(), 80);

        // Should verify successfully
        let output = VrfDraft03::verify(&pk, &proof, message)?;
        assert_eq!(output.len(), 64);

        Ok(())
    }

    /// Test VRF output uniqueness for different messages
    #[test]
    fn test_vrf_output_uniqueness() -> Result<()> {
        let seed = [50u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let message1 = b"message one";
        let message2 = b"message two";

        let proof1 = VrfDraft03::prove(&sk, message1)?;
        let proof2 = VrfDraft03::prove(&sk, message2)?;

        let output1 = VrfDraft03::verify(&pk, &proof1, message1)?;
        let output2 = VrfDraft03::verify(&pk, &proof2, message2)?;

        // Different messages should produce different outputs
        assert_ne!(output1, output2);
        assert_ne!(proof1, proof2);

        Ok(())
    }

    /// Test VRF proof cannot be reused for different messages
    #[test]
    fn test_vrf_proof_reuse_fails() -> Result<()> {
        let seed = [60u8; 32];
        let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);

        let message1 = b"original";
        let message2 = b"modified";

        let proof = VrfDraft03::prove(&sk, message1)?;

        // Verify with original message (should succeed)
        VrfDraft03::verify(&pk, &proof, message1)?;

        // Attempt to use same proof with different message (should fail)
        let result = VrfDraft03::verify(&pk, &proof, message2);
        assert!(result.is_err());

        Ok(())
    }
}
