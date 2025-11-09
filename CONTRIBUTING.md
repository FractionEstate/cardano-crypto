# Contributing to Cardano Crypto

Thank you for your interest in contributing to the Cardano Crypto library!

## Development Setup

1. Install Rust (1.91 or later):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone the repository:
```bash
git clone https://github.com/FractionEstate/Cardano-Crypto.git
cd Cardano-Crypto
```

3. Build the project:
```bash
cargo build --all-features
```

4. Run tests:
```bash
cargo test --all-features
```

## Project Structure

```
cardano-crypto/
├── src/
│   ├── lib.rs          # Main library with feature flags
│   ├── common.rs       # Shared utilities and error types
│   ├── hash.rs         # Blake2b and SHA implementations
│   ├── seed.rs         # Deterministic key derivation
│   ├── dsign.rs        # Ed25519 digital signatures
│   ├── vrf.rs          # VRF Draft-03 and Draft-13
│   ├── kes.rs          # KES module root
│   ├── kes/
│   │   ├── single.rs   # Single-period KES
│   │   ├── sum.rs      # Sum KES variants
│   │   └── compact_sum.rs  # Compact Sum KES variants
│   └── cbor.rs         # Optional CBOR support
├── examples/           # Usage examples
└── tests/              # Integration tests
```

## Implementation Roadmap

### Phase 1: Core Infrastructure (Current)
- [x] Project structure with feature flags
- [x] Common traits and error types
- [x] Module stubs with documentation
- [ ] Extract Blake2b from cardano-base-rust
- [ ] Extract Ed25519 from cardano-base-rust

### Phase 2: VRF Migration
- [ ] Migrate VRF Draft-03 from FractionEstate/cardano-VRF
- [ ] Migrate VRF Draft-13 from FractionEstate/cardano-VRF
- [ ] Migrate Cardano compatibility layer
- [ ] Port VRF test vectors

### Phase 3: KES Implementation
- [ ] Implement SingleKES
- [ ] Implement Sum KES hierarchy (Sum0-Sum7)
- [ ] Implement Compact Sum KES (CompactSum0-CompactSum7)
- [ ] Port KES test vectors

### Phase 4: Testing & Optimization
- [ ] Comprehensive test suite
- [ ] Benchmarks for all algorithms
- [ ] Security audit
- [ ] Performance optimization

## Coding Guidelines

### Style
- Follow Rust standard formatting (`cargo fmt`)
- Run clippy and fix warnings (`cargo clippy --all-features`)
- Write documentation for all public APIs
- Include examples in rustdoc

### Documentation
- Use `///` for public item documentation
- Use `//!` for module-level documentation
- Include examples in documentation:
```rust
/// Example function
///
/// # Examples
///
/// ```
/// use cardano_crypto::hash::Blake2b256;
/// let hash = Blake2b256::hash(b"data");
/// ```
pub fn example() {}
```

### Testing
- Write unit tests in the same file as the implementation
- Write integration tests in `tests/` directory
- Test with all feature combinations:
```bash
cargo test --no-default-features
cargo test --all-features
cargo test --features vrf
cargo test --features kes
```

### Error Handling
- Use `Result<T>` from `crate::common`
- Return descriptive errors
- Avoid panics in library code (use `Result` instead)

## Extraction Guidelines

When extracting code from cardano-base-rust:

1. **Preserve Haskell compatibility**: Maintain byte-level compatibility
2. **Remove external dependencies**: Replace with in-house implementations
3. **Add documentation**: Explain algorithms and implementation choices
4. **Port test vectors**: Include official Cardano test vectors
5. **Feature gate appropriately**: Use feature flags for optional components

### Example Extraction Checklist

- [ ] Copy source files from cardano-base-rust
- [ ] Remove external crypto crate dependencies
- [ ] Update imports to use our modules
- [ ] Add comprehensive rustdoc
- [ ] Port associated test vectors
- [ ] Verify binary compatibility
- [ ] Add feature flags if optional
- [ ] Update module re-exports in lib.rs

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests: `cargo test --all-features`
5. Run fmt: `cargo fmt`
6. Run clippy: `cargo clippy --all-features`
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### PR Requirements
- All tests pass
- No clippy warnings
- Code is formatted with `cargo fmt`
- Documentation is updated
- CHANGELOG.md is updated

## Security

If you discover a security vulnerability, please email security@fractionestate.com instead of opening a public issue.

## Questions?

Open an issue or discussion on GitHub!

## License

By contributing, you agree that your contributions will be licensed under both MIT and Apache-2.0 licenses.
