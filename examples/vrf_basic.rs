//! Basic VRF usage example
//!
//! Demonstrates VRF proof generation and verification using Cardano-compatible
//! VRF Draft-03 implementation.

use cardano_crypto::vrf::VrfDraft03;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cardano VRF Basic Usage Example ===\n");

    // Generate a keypair from a seed
    let seed = [42u8; 32];
    let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);

    println!("Generated keypair from seed:");
    println!("  Secret key: {} bytes", secret_key.len());
    println!("  Public key: {} bytes ({}...)",
        public_key.len(),
        hex::encode(&public_key[0..8])
    );
    println!();

    // Create a VRF proof
    let message = b"Cardano block slot 12345";
    println!("Message: {}", String::from_utf8_lossy(message));

    let proof = VrfDraft03::prove(&secret_key, message)?;
    println!("Proof generated ({} bytes): {}...",
        proof.len(),
        hex::encode(&proof[0..16])
    );
    println!();

    // Verify the proof and get VRF output
    let output = VrfDraft03::verify(&public_key, &proof, message)?;
    println!("✓ Proof verified successfully!");
    println!("VRF output ({} bytes): {}...",
        output.len(),
        hex::encode(&output[0..16])
    );
    println!();

    // Extract VRF output from proof without full verification (faster)
    let hash = VrfDraft03::proof_to_hash(&proof)?;
    println!("VRF hash (from proof): {}...", hex::encode(&hash[0..16]));

    // Verify they match
    assert_eq!(output, hash);
    println!("✓ Output matches hash extraction");
    println!();

    // Demonstrate that VRF output is deterministic
    let proof2 = VrfDraft03::prove(&secret_key, message)?;
    let output2 = VrfDraft03::verify(&public_key, &proof2, message)?;

    assert_eq!(output, output2);
    println!("✓ VRF output is deterministic for the same message");

    // Demonstrate that different messages produce different outputs
    let different_message = b"Different message - slot 99999";
    let different_proof = VrfDraft03::prove(&secret_key, different_message)?;
    let different_output = VrfDraft03::verify(&public_key, &different_proof, different_message)?;

    assert_ne!(output, different_output);
    println!("✓ Different messages produce different VRF outputs");
    println!();

    // Demonstrate verification failure with wrong message
    println!("Testing verification with wrong message...");
    let wrong_result = VrfDraft03::verify(&public_key, &proof, b"wrong message");
    assert!(wrong_result.is_err());
    println!("✓ Verification correctly fails with wrong message");

    println!("\n=== All VRF tests passed! ===");

    Ok(())
}

// Helper function to encode bytes as hex
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
