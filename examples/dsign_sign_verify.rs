//! Basic DSIGN usage example
//!
//! Demonstrates digital signature generation and verification with Ed25519.

use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cardano Ed25519 Digital Signature Example ===\n");

    // Display algorithm parameters
    println!("Ed25519 Parameters:");
    println!("  Signing key: {} bytes", Ed25519::SIGNING_KEY_SIZE);
    println!(
        "  Verification key: {} bytes",
        Ed25519::VERIFICATION_KEY_SIZE
    );
    println!("  Signature size: {} bytes", Ed25519::SIGNATURE_SIZE);
    println!();

    // Generate a keypair from a seed
    let seed = [42u8; 32];
    let signing_key = Ed25519::gen_key(&seed);
    let verification_key = Ed25519::derive_verification_key(&signing_key);

    println!("Generated keypair from seed:");
    println!(
        "  Verification key: {} bytes ({}...)",
        verification_key.as_bytes().len(),
        hex::encode(&verification_key.as_bytes()[0..8])
    );
    println!();

    // Sign a message
    let message = b"Cardano transaction data";
    println!("Message: {}", String::from_utf8_lossy(message));

    let signature = Ed25519::sign(&signing_key, message);
    println!(
        "Signature generated ({} bytes): {}...",
        signature.as_bytes().len(),
        hex::encode(&signature.as_bytes()[0..16])
    );
    println!();

    // Verify the signature
    Ed25519::verify(&verification_key, message, &signature)?;
    println!("✓ Signature verified successfully!");
    println!();

    // Demonstrate determinism
    let signature2 = Ed25519::sign(&signing_key, message);
    assert_eq!(signature.as_bytes(), signature2.as_bytes());
    println!("✓ Ed25519 signatures are deterministic");

    // Demonstrate verification failure with wrong message
    println!("\nTesting verification with wrong message...");
    let wrong_result = Ed25519::verify(&verification_key, b"wrong message", &signature);
    assert!(wrong_result.is_err());
    println!("✓ Verification correctly fails with wrong message");

    // Test with empty message
    println!("\nTesting with empty message...");
    let empty_sig = Ed25519::sign(&signing_key, b"");
    Ed25519::verify(&verification_key, b"", &empty_sig)?;
    println!("✓ Empty message signing/verification works");

    // Test with large message
    println!("\nTesting with large message (10 KB)...");
    let large_message = vec![0xAB; 10_000];
    let large_sig = Ed25519::sign(&signing_key, &large_message);
    Ed25519::verify(&verification_key, &large_message, &large_sig)?;
    println!("✓ Large message signing/verification works");

    println!("\n=== All Ed25519 tests passed! ===");

    Ok(())
}

// Helper function to encode bytes as hex
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
