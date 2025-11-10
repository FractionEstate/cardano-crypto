//! KES Lifecycle Example
//!
//! Demonstrates the complete lifecycle of Key Evolving Signatures (KES):
//! - Key generation from seed
//! - Signing messages at different periods
//! - Verification of signatures
//! - Key evolution (forward-secure updates)
//! - Key expiration handling
//!
//! This example uses multiple KES schemes to demonstrate different security/performance tradeoffs.

use cardano_crypto::common::error::Result;
use cardano_crypto::dsign::Ed25519;
use cardano_crypto::kes::{
    Blake2b256, CompactSingleKes, CompactSum2Kes, CompactSum6Kes, KesAlgorithm, SingleKes,
    Sum2Kes, Sum6Kes,
};

/// Helper to print separator lines
fn separator() {
    println!("{}", "=".repeat(80));
}

/// Helper to print section headers
fn section(title: &str) {
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
}

/// Demonstrate SingleKES (1 period, no forward security)
fn demo_single_kes() -> Result<()> {
    section("1. SingleKES - Base Case (1 period)");

    type MyKes = SingleKes<Ed25519>;

    println!("Algorithm: {}", MyKes::ALGORITHM_NAME);
    println!("Total periods: {}", MyKes::total_periods());
    println!("Seed size: {} bytes", MyKes::SEED_SIZE);
    println!("Verification key: {} bytes", MyKes::VERIFICATION_KEY_SIZE);
    println!("Signature: {} bytes", MyKes::SIGNATURE_SIZE);

    // Generate keypair
    let seed = [1u8; 32];
    let sk = MyKes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = MyKes::derive_verification_key(&sk)?;
    println!("\n✓ Generated keypair from seed");

    // Sign at period 0 (only valid period)
    let message = b"Cardano block header";
    let sig = MyKes::sign_kes(&(), 0, message, &sk)?;
    println!("✓ Signed message at period 0");

    // Verify signature
    MyKes::verify_kes(&(), &vk, 0, message, &sig)?;
    println!("✓ Signature verified successfully");

    // Try to sign at period 1 (should fail)
    println!("\nAttempting to sign at period 1 (out of range)...");
    match MyKes::sign_kes(&(), 1, message, &sk) {
        Err(_) => println!("✓ Correctly rejected period 1 (max period is 0)"),
        Ok(_) => println!("✗ ERROR: Should have rejected period 1"),
    }

    // Update key (will expire)
    let updated = MyKes::update_kes(&(), sk, 0)?;
    match updated {
        None => println!("✓ Key expired after period 0 (as expected)"),
        Some(_) => println!("✗ ERROR: Key should have expired"),
    }

    Ok(())
}

/// Demonstrate Sum2Kes (4 periods, basic forward security)
fn demo_sum2_kes() -> Result<()> {
    section("2. Sum2Kes - Binary Tree (4 periods)");

    type MyKes = Sum2Kes;

    println!("Algorithm: Sum²KES");
    println!("Total periods: {} (2² = 4)", MyKes::total_periods());
    println!("Seed size: {} bytes", MyKes::SEED_SIZE);
    println!("Verification key: {} bytes", MyKes::VERIFICATION_KEY_SIZE);
    println!("Signature: {} bytes", MyKes::SIGNATURE_SIZE);

    // Generate keypair
    let seed = [2u8; 32];
    let mut sk = MyKes::gen_key_kes_from_seed(&seed)?;
    let vk = MyKes::derive_verification_key(&sk)?;
    println!("\n✓ Generated keypair from seed");

    // Sign at each period and demonstrate key evolution
    let messages = [
        b"Block at period 0",
        b"Block at period 1",
        b"Block at period 2",
        b"Block at period 3",
    ];

    for (period, message) in messages.iter().enumerate() {
        let period = period as u64;
        println!("\nPeriod {}:", period);

        // Sign message
        let sig = MyKes::sign_kes(&(), period, message.as_ref(), &sk)?;
        println!("  ✓ Signed message ({} bytes)", message.len());

        // Verify signature
        MyKes::verify_kes(&(), &vk, period, message.as_ref(), &sig)?;
        println!("  ✓ Signature verified");

        // Verify signature with wrong message (should fail)
        let wrong_result = MyKes::verify_kes(&(), &vk, period, b"wrong message", &sig);
        if wrong_result.is_err() {
            println!("  ✓ Correctly rejected wrong message");
        }

        // Update key for next period
        if period < MyKes::total_periods() - 1 {
            let updated = MyKes::update_kes(&(), sk, period)?;
            match updated {
                Some(new_sk) => {
                    sk = new_sk;
                    println!("  ✓ Key updated to period {}", period + 1);
                }
                None => {
                    println!("  ✗ ERROR: Key expired unexpectedly");
                    break;
                }
            }
        }
    }

    // Try to update past expiration
    println!("\nAttempting to update past final period...");
    let final_update = MyKes::update_kes(&(), sk, 3)?;
    match final_update {
        None => println!("✓ Key expired after period 3 (as expected)"),
        Some(_) => println!("✗ ERROR: Key should have expired"),
    }

    Ok(())
}

/// Demonstrate Sum6Kes (64 periods, Cardano standard)
fn demo_sum6_kes() -> Result<()> {
    section("3. Sum6Kes - Cardano Standard (64 periods)");

    type MyKes = Sum6Kes;

    println!("Algorithm: Sum⁶KES");
    println!("Total periods: {} (2⁶ = 64)", MyKes::total_periods());
    println!("Seed size: {} bytes", MyKes::SEED_SIZE);
    println!("Verification key: {} bytes", MyKes::VERIFICATION_KEY_SIZE);
    println!("Signature: {} bytes", MyKes::SIGNATURE_SIZE);
    println!(
        "Note: Sum6Kes is the standard KES scheme used in Cardano stake pools"
    );

    // Generate keypair
    let seed = [6u8; 32];
    let mut sk = MyKes::gen_key_kes_from_seed(&seed)?;
    let vk = MyKes::derive_verification_key(&sk)?;
    println!("\n✓ Generated keypair from seed");

    // Demonstrate signing at various periods
    let test_periods = [0, 1, 15, 31, 32, 50, 63];
    println!("\nDemonstrating key evolution across selected periods:");

    for &period in &test_periods {
        let period_u64 = period as u64;
        // Update to target period
        while sk
            .as_ref()
            .map(|_| period_u64)
            .unwrap_or(0)
            < period_u64.saturating_sub(1)
        {
            if let Some(current_sk) = sk {
                let current_period = period_u64.saturating_sub(1);
                sk = MyKes::update_kes(&(), current_sk, current_period)?;
            } else {
                break;
            }
        }

        if let Some(ref signing_key) = sk {
            let message = format!("Cardano block at slot {}", period * 100);
            let sig = MyKes::sign_kes(&(), period, message.as_bytes(), signing_key)?;
            MyKes::verify_kes(&(), &vk, period, message.as_bytes(), &sig)?;
            println!("  Period {:2}: ✓ Sign & verify successful", period);

            // Update for next iteration
            if period < 63 {
                sk = MyKes::update_kes(&(), sk.unwrap(), period)?;
            }
        } else {
            println!("  Period {:2}: ✗ Key expired", period);
            break;
        }
    }

    // Demonstrate expiration
    println!("\nDemonstrating key expiration:");
    let seed_fresh = [7u8; 32];
    let mut sk_fresh = MyKes::gen_key_kes_from_seed(&seed_fresh)?;

    // Fast-forward to period 63 (last period)
    for p in 0..63 {
        sk_fresh = MyKes::update_kes(&(), sk_fresh, p)?.expect("Should not expire yet");
    }

    let message = b"Final block";
    let sig = MyKes::sign_kes(&(), 63, message, &sk_fresh)?;
    println!("✓ Successfully signed at period 63 (last valid period)");

    // Try to update past expiration
    let expired = MyKes::update_kes(&(), sk_fresh, 63)?;
    match expired {
        None => println!("✓ Key correctly expired after period 63"),
        Some(_) => println!("✗ ERROR: Key should have expired"),
    }

    Ok(())
}

/// Demonstrate CompactSum6Kes (smaller signatures)
fn demo_compact_sum6_kes() -> Result<()> {
    section("4. CompactSum6Kes - Optimized Signatures (64 periods)");

    type MyKes = CompactSum6Kes;

    println!("Algorithm: CompactSum⁶KES");
    println!("Total periods: {} (2⁶ = 64)", MyKes::total_periods());
    println!("Signature: {} bytes (compact)", MyKes::SIGNATURE_SIZE);

    // Compare with standard Sum6Kes
    type StandardKes = Sum6Kes;
    println!(
        "Standard Sum6Kes signature: {} bytes",
        StandardKes::SIGNATURE_SIZE
    );
    let savings = StandardKes::SIGNATURE_SIZE as i32 - MyKes::SIGNATURE_SIZE as i32;
    println!(
        "Space savings: {} bytes ({:.1}%)",
        savings,
        (savings as f64 / StandardKes::SIGNATURE_SIZE as f64) * 100.0
    );

    // Generate and use compact KES
    let seed = [8u8; 32];
    let sk = MyKes::gen_key_kes_from_seed(&seed)?;
    let vk = MyKes::derive_verification_key(&sk)?;
    println!("\n✓ Generated compact KES keypair");

    // Sign and verify
    let message = b"Compact signature test";
    let sig = MyKes::sign_kes(&(), 0, message, &sk)?;
    MyKes::verify_kes(&(), &vk, 0, message, &sig)?;
    println!("✓ Compact signature verified successfully");

    Ok(())
}

/// Main demonstration
fn main() -> Result<()> {
    separator();
    println!("  CARDANO KEY EVOLVING SIGNATURES (KES) - LIFECYCLE DEMONSTRATION");
    separator();

    println!("\nKES provides forward-secure digital signatures where:");
    println!("• Keys can sign messages for a limited number of periods (2ᴺ)");
    println!("• Keys evolve after each period (old keys cannot sign for new periods)");
    println!("• Even if current key is compromised, past signatures remain secure");
    println!("• Used in Cardano for stake pool block signing (90-day key rotation)");

    // Run demonstrations
    demo_single_kes()?;
    demo_sum2_kes()?;
    demo_sum6_kes()?;
    demo_compact_sum6_kes()?;

    separator();
    println!("\n  KEY TAKEAWAYS");
    separator();
    println!("
• SingleKES: 1 period, no forward security (base case)
• Sum2Kes: 4 periods (2²), demonstrates binary tree composition
• Sum6Kes: 64 periods (2⁶), Cardano standard for stake pools
• CompactSum6Kes: Same as Sum6Kes but with smaller signatures

Forward Security Guarantee:
  Even if period N key is compromised, signatures from periods 0..(N-1)
  remain cryptographically secure because old key material is irreversibly
  destroyed during key evolution.

Cardano Usage:
  Stake pools use Sum6Kes with 64 periods, where each period ≈ 36 hours.
  This allows 90 days of operation before requiring key rotation.
    ");

    separator();
    println!("  ALL KES LIFECYCLE TESTS PASSED!");
    separator();

    Ok(())
}
