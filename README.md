# Cardano Crypto - Pure Rust Implementation

[![Crates.io](https://img.shields.io/crates/v/cardano-crypto.svg)](https://crates.io/crates/cardano-crypto/
[![Documentation](https://docs.rs/cardano-crypto/badge.svg)](https://docs.rs/cardano-crypto)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://fractionestate.github.io/cardano-crypto/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)](https://www.rust-lang.org)
[![CI](https://github.com/FractionEstate/cardano-crypto/workflows/CI/badge.svg)](https://github.com/FractionEstate/cardano-crypto/actions)

Pure Rust implementation of Cardano cryptographic primitives, providing a unified interface for **VRF** (Verifiable Random Functions), **KES** (Key Evolving Signatures), **DSIGN** (Digital Signatures), and **Hash** algorithms.

This crate consolidates all Cardano cryptographic components into a single, cohesive package with zero external cryptographic dependencies. All implementations are in-house, ensuring full control, auditability, and binary compatibility with Cardano consensus requirements.




## Features## Features



- **VRF (Verifiable Random Functions)**: IETF VRF Draft-03 and Draft-13 with Cardano libsodium compatibility- ✅ **Complete KES Implementation** - SingleKES, SumKES, CompactSingleKES, CompactSumKES

- **KES (Key Evolving Signatures)**: Single, Sum, and Compact variants for forward-secure signatures- ✅ **Binary Compatible** - Matches Haskell `cardano-crypto-class` implementation

- **DSIGN (Digital Signatures)**: Ed25519 signatures with deterministic key generation- ✅ **No Standard Library Required** - `no_std` compatible with `alloc`

- **Hash Algorithms**: Blake2b (224/256/512), SHA-2 family, and other Cardano hash functions- ✅ **Zero Unsafe Code** - Pure safe Rust implementation

- **Seed Management**: Deterministic entropy generation and key derivation- ✅ **Comprehensive Tests** - Full test vector coverage from Cardano

- **CBOR Support**: Optional serialization for Cardano binary formats- ✅ **Well Documented** - Complete API documentation and examples

- **no_std Compatible**: Works in embedded and WebAssembly environments

- **Feature Flags**: Include only the components you need## What is KES?



## InstallationKey Evolving Signatures (KES) provide **forward security** - once a key evolves to a new period, it cannot sign for previous periods, even if compromised. This is critical for blockchain consensus where stake pool operators must protect against key theft.



Add to your `Cargo.toml`:### KES Families



```toml| Algorithm | Periods | Use Case |

[dependencies]|-----------|---------|----------|

cardano-crypto = "0.1"| `SingleKES` | 1 | Base case (wraps Ed25519) |

```| `SumKES` | 2^n | Standard composition with full VK storage |

| `CompactSingleKES` | 1 | Base with embedded VK in signature |

### Selective Features| `CompactSumKES` | 2^n | Optimized composition (smaller signatures) |



Include only what you need:## Installation



```tomlAdd to your `Cargo.toml`:

# Only VRF

cardano-crypto = { version = "0.1", default-features = false, features = ["vrf"] }```toml

[dependencies]

# VRF + KEScardano-kes = "0.1"

cardano-crypto = { version = "0.1", default-features = false, features = ["vrf", "kes"] }```



# Everything with metrics### Feature Flags

cardano-crypto = { version = "0.1", features = ["metrics", "logging"] }

```toml

# no_std with alloc[dependencies]

cardano-crypto = { version = "0.1", default-features = false, features = ["alloc", "vrf"] }cardano-kes = { version = "0.1", features = ["serde"] }

``````



## Quick StartAvailable features:

- `std` (default) - Standard library support

### VRF (Verifiable Random Function)- `serde` - Serialization support for key types

- `kes-metrics` - Lightweight metrics for benchmarking

```rust

use cardano_crypto::vrf::{VrfDraft03, VrfKeyPair, VrfProof};For `no_std` environments:

```toml

// Generate keypair from seed[dependencies]

let seed = [0u8; 32];cardano-kes = { version = "0.1", default-features = false }

let keypair = VrfKeyPair::from_seed(&seed);```



// Create proof## Quick Start

let message = b"epoch-nonce";

let proof = VrfProof::prove(&keypair, message)?;```rust

use cardano_kes::*;

// Verify proof

let output = proof.verify(&keypair.public_key(), message)?;// Generate a signing key from a seed

let seed = vec![0u8; Sum2Kes::SEED_SIZE];

// Use VRF output for randomnesslet mut signing_key = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;

println!("VRF output: {:?}", output.as_bytes());let verification_key = Sum2Kes::derive_verification_key(&signing_key)?;

```

// Sign a message at period 0

### KES (Key Evolving Signatures)let message = b"Hello, Cardano!";

let period = 0;

```rustlet signature = Sum2Kes::sign_kes(&(), period, message, &signing_key)?;

use cardano_crypto::kes::{Sum6Kes, KesAlgorithm};

// Verify the signature

// Generate KES key for 2^6 = 64 periodsSum2Kes::verify_kes(&(), &verification_key, period, message, &signature)?;

let seed = [0u8; 32];

let mut signing_key = Sum6Kes::gen_key_from_seed(&seed)?;// Evolve key to next period

let verification_key = Sum6Kes::derive_verification_key(&signing_key)?;signing_key = Sum2Kes::update_kes(&(), signing_key, period)?

    .expect("key is still valid");

// Sign at period 0

let period = 0;// Key can now sign for period 1, but NOT period 0 (forward security)

let message = b"block-header";```

let signature = Sum6Kes::sign(&signing_key, period, message)?;

## KES Algorithm Details

// Verify signature

Sum6Kes::verify(&verification_key, period, message, &signature)?;### Single-period KES (SingleKES)



// Evolve key to next periodThe simplest KES - wraps Ed25519 DSIGN for a single period:

signing_key = Sum6Kes::update_key(signing_key, period + 1)?;

``````rust

use cardano_kes::*;

### DSIGN (Digital Signatures)

let seed = vec![0u8; SingleKes::SEED_SIZE];

```rustlet signing_key = SingleKes::gen_key_kes_from_seed_bytes(&seed)?;

use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};let vk = SingleKes::derive_verification_key(&signing_key)?;



// Generate keypair// Only period 0 is valid

let seed = [0u8; 32];let sig = SingleKes::sign_kes(&(), 0, b"message", &signing_key)?;

let signing_key = Ed25519::gen_key(&seed);SingleKes::verify_kes(&(), &vk, 0, b"message", &sig)?;

let verification_key = Ed25519::derive_verification_key(&signing_key);```



// Sign message### Multi-period Sum KES

let message = b"transaction-data";

let signature = Ed25519::sign(&signing_key, message);Binary tree composition supporting 2^n periods:



// Verify signature```rust

Ed25519::verify(&verification_key, message, &signature)?;use cardano_kes::*;

```

// Sum2Kes = 2^2 = 4 periods (0, 1, 2, 3)

### Hash Functionslet seed = vec![0u8; Sum2Kes::SEED_SIZE];

let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;

```rustlet vk = Sum2Kes::derive_verification_key(&sk)?;

use cardano_crypto::hash::{Blake2b256, Hash};

// Sign and evolve through all periods

// Hash data with Blake2b-256for period in 0..Sum2Kes::total_periods() {

let data = b"block-content";    let message = format!("Period {}", period);

let hash = Blake2b256::hash(data);    let sig = Sum2Kes::sign_kes(&(), period, message.as_bytes(), &sk)?;

println!("Blake2b-256: {:?}", hash);    Sum2Kes::verify_kes(&(), &vk, period, message.as_bytes(), &sig)?;



// Hash concatenation (for Merkle trees)    // Update for next period

let left = Blake2b256::hash(b"left-branch");    if period + 1 < Sum2Kes::total_periods() {

let right = Blake2b256::hash(b"right-branch");        sk = Sum2Kes::update_kes(&(), sk, period)?

let root = Blake2b256::hash_concat(&left, &right);            .expect("key still valid");

```    }

}

## Architecture```



### Component Independence with Shared Infrastructure### Compact Sum KES (Optimized)



```More efficient signatures by embedding off-path verification keys:

cardano-crypto/

├── vrf/           # VRF Draft-03 & Draft-13```rust

├── kes/           # KES hierarchy (Single, Sum, Compact)use cardano_kes::*;

├── dsign/         # Ed25519 signatures

├── hash/          # Blake2b, SHA family// CompactSum3Kes = 2^3 = 8 periods with smaller signatures

├── seed/          # Deterministic key derivationlet seed = vec![0u8; CompactSum3Kes::SEED_SIZE];

├── cbor/          # Optional CBOR serializationlet mut sk = CompactSum3Kes::gen_key_kes_from_seed_bytes(&seed)?;

└── common/        # Shared traits and utilitieslet vk = CompactSum3Kes::derive_verification_key(&sk)?;

```

let sig = CompactSum3Kes::sign_kes(&(), 0, b"message", &sk)?;

### Feature Flag ArchitectureCompactSum3Kes::verify_kes(&(), &vk, 0, b"message", &sig)?;

```

Users can minimize binary size by selecting only needed components:

## Type Aliases

- `vrf` - Enables VRF (automatically includes `dsign` and `hash`)

- `kes` - Enables KES (automatically includes `dsign` and `hash`)Pre-configured KES algorithms for different period counts:

- `dsign` - Enables digital signatures (automatically includes `hash`)

- `hash` - Enables hash functions (minimal, no dependencies)```rust

- `cbor` - Optional CBOR serialization support// Sum family (using Blake2b-256)

- `serde` - Optional serde serialization for key typespub type Sum0Kes = SingleKes<Ed25519>;           // 1 period

- `metrics` - Prometheus-style metrics collectionpub type Sum1Kes = SumKes<Sum0Kes, Blake2b256>;  // 2 periods

- `logging` - Structured logging for debuggingpub type Sum2Kes = SumKes<Sum1Kes, Blake2b256>;  // 4 periods

pub type Sum3Kes = SumKes<Sum2Kes, Blake2b256>;  // 8 periods

## Why Unified Package?pub type Sum4Kes = SumKes<Sum3Kes, Blake2b256>;  // 16 periods

pub type Sum5Kes = SumKes<Sum4Kes, Blake2b256>;  // 32 periods

This crate consolidates VRF, KES, DSIGN, and Hash into one package because:pub type Sum6Kes = SumKes<Sum5Kes, Blake2b256>;  // 64 periods

pub type Sum7Kes = SumKes<Sum6Kes, Blake2b256>;  // 128 periods

1. **Shared Dependencies**: All components need Blake2b hashing and Ed25519 signatures

2. **Atomic Versioning**: Guarantees all components work together (no version conflicts)// Compact sum family (optimized)

3. **Zero External Crypto**: Full in-house implementation for auditabilitypub type CompactSum0Kes = CompactSingleKes<Ed25519>;

4. **Haskell Parity**: Matches `cardano-crypto-class` package structurepub type CompactSum1Kes = CompactSumKes<CompactSum0Kes, Blake2b256>;

5. **Simpler Dependencies**: One crate instead of managing 6+ separate packages// ... up to CompactSum7Kes

6. **Better Testing**: Integration tests across all components```

7. **Reduced Binary Bloat**: Shared code compiled once

## Architecture

See [PACKAGE_STRATEGY_ANALYSIS.md](PACKAGE_STRATEGY_ANALYSIS.md) for detailed rationale.

This crate is extracted from the Cardano ecosystem's Rust cryptography implementation:

## Binary Compatibility

```

All implementations maintain byte-level compatibility with:cardano-kes/

- Haskell `cardano-crypto-class` library├── src/

- Cardano consensus layer requirements│   ├── lib.rs              # Main module and exports

- Official Cardano test vectors│   ├── error.rs            # Error types

│   ├── period.rs           # Period type and utilities

## Security│   ├── traits.rs           # Core KesAlgorithm trait

│   ├── single.rs           # SingleKES implementation

- **No External Crypto Dependencies**: All cryptographic primitives implemented in-house│   ├── compact_single.rs   # CompactSingleKES

- **Constant-Time Operations**: Timing-safe comparisons where applicable│   ├── sum.rs              # SumKES family

- **Memory Safety**: Pure Rust with `#![deny(unsafe_code)]` where possible│   ├── compact_sum.rs      # CompactSumKES family

- **Audit-Friendly**: Single codebase for comprehensive security review│   ├── hash.rs             # Blake2b hash algorithms

│   └── metrics.rs          # Optional metrics

## no_std Support├── examples/

│   └── basic_usage.rs

This crate supports `no_std` environments with `alloc`:└── tests/

    └── integration_tests.rs

```toml```

[dependencies]

cardano-crypto = { version = "0.1", default-features = false, features = ["alloc", "vrf"] }## Testing

```

## Development

### Building

```bash
# Development build (fast compilation, no optimization)
cargo build --all-features

# Production release build (maximum optimization)
cargo build --release --all-features

# Build only VRF component
cargo build --no-default-features --features vrf

# Build with metrics enabled
cargo build --features kes-metrics
```

#### Build Profiles

This crate includes optimized build profiles in `Cargo.toml`:

- **dev** - Fast compilation, no optimization (default for `cargo build`)
  - `opt-level = 0` - No optimization
  - `incremental = true` - Fast rebuilds
  - `codegen-units = 256` - Parallel compilation

- **release** - Maximum optimization (`cargo build --release`)
  - `opt-level = 3` - Maximum optimization
  - `lto = "fat"` - Full Link-Time Optimization
  - `codegen-units = 1` - Best optimization quality
  - `strip = true` - Smaller binaries
  - `panic = 'abort'` - Smaller code size

- **release-with-debug** - Release optimizations + debug symbols (for profiling)
- **bench** - Optimized for benchmarking
- **test** - Balanced optimization for faster test execution

### Testing

```bash
# Run all tests
cargo test --all-features

# Run specific test
cargo test single_kes_basic

# Run with test vectors
cargo test --test vrf_golden_tests
cargo test --test kes_golden_tests

# Run examples
cargo run --example vrf_basic
cargo run --example kes_lifecycle
cargo run --example dsign_sign_verify

# Generate documentation
cargo doc --all-features --open
```

## Binary Compatibility

This implementation maintains binary compatibility with Haskell's `cardano-crypto-class`:

- ✅ Verification key serialization matches byte-for-byte
- ✅ Signature format identical to Haskell implementation
- ✅ All official Cardano test vectors pass
- ✅ Hash algorithm (Blake2b-256) matches Haskell exactly## Security Considerations



# Test specific component### Forward Security

cargo test --features vrf

Once a key evolves past a period, it **cannot** sign for that period:

# Run with test vectors

cargo test --test vrf_vectors```rust

```let mut sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;



## Roadmap// Sign for period 0

let sig0 = Sum2Kes::sign_kes(&(), 0, b"msg0", &sk)?;

- [x] Project structure and feature flag design

- [ ] Extract Blake2b implementation (from cardano-base-rust)// Evolve to period 1

- [ ] Extract Ed25519 implementation (from cardano-base-rust)sk = Sum2Kes::update_kes(&(), sk, 0)?.unwrap();

- [ ] Migrate VRF implementation (from FractionEstate/cardano-VRF)

- [ ] Implement KES hierarchy (Single, Sum0-7, CompactSum0-7)// ❌ Cannot sign for period 0 anymore!

- [ ] Add SHA-2 hash family// This will return an error

- [ ] CBOR serialization supportlet result = Sum2Kes::sign_kes(&(), 0, b"msg0", &sk);

- [ ] Comprehensive test vector suiteassert!(result.is_err());

- [ ] Benchmarks and performance optimization```

- [ ] Security audit

- [ ] Publish to crates.io### Key Zeroization



## ContributingSigning keys are automatically zeroized when dropped:



Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.```rust

{

## License    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;

    // Use sk...

Licensed under either of:} // sk is zeroized here

```

- MIT license ([LICENSE-MIT](LICENSE-MIT))

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))### No Unsafe Code



at your option.This crate uses **zero unsafe code** - all operations are safe Rust.



## Acknowledgments## Related Crates



This implementation is based on:Part of the Cardano Rust ecosystem:

- Haskell `cardano-crypto-class` from [cardano-base](https://github.com/IntersectMBO/cardano-base)

- IETF VRF specifications (Draft-03 and Draft-13)- [`cardano-vrf`](https://crates.io/crates/cardano-vrf) - Verifiable Random Functions

- "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures" by Malkin, Micciancio, and Miner- `cardano-dsign` - Digital signatures (coming soon)

- `cardano-cbor` - CBOR encoding (coming soon)

## Links

## Contributing

- [Documentation](https://docs.rs/cardano-crypto)

- [Repository](https://github.com/FractionEstate/Cardano-Crypto)We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- [Issue Tracker](https://github.com/FractionEstate/Cardano-Crypto/issues)

- [Haskell Reference](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class)### Development


```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Build docs
cargo doc --open

# Run benches
cargo bench
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Acknowledgments

This implementation is based on the Haskell `cardano-crypto-class` library and the academic paper:

> "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
> by Tal Malkin, Daniele Micciancio, and Sara Miner
> https://eprint.iacr.org/2001/034

Special thanks to:
- The Cardano Foundation
- IOHK/Input Output
- The Rust Cardano community
