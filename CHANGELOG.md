# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure for unified `cardano-crypto` package
- Feature flag architecture for selective component compilation
- Module stubs for VRF, KES, DSIGN, Hash, Seed, and CBOR
- Comprehensive documentation and README
- MIT and Apache-2.0 dual licensing

### TODO
- [ ] Extract Blake2b implementation from cardano-base-rust
- [ ] Extract Ed25519 implementation from cardano-base-rust
- [ ] Migrate VRF Draft-03 and Draft-13 from FractionEstate/cardano-VRF
- [ ] Implement KES hierarchy (Single, Sum0-7, CompactSum0-7)
- [ ] Add test vector suite
- [ ] Performance benchmarks
- [ ] Security audit

## [0.1.0] - TBD

### Added
- First release (planned)
