# CI/CD Quick Reference

## GitHub Actions Workflows

### Main Workflows

| Workflow | Trigger | Purpose | Status |
|----------|---------|---------|--------|
| **ci.yml** | Push/PR to main | Full test suite, clippy, fmt, docs | ✅ Ready |
| **publish.yml** | Git tags (v*.*.*) | Publish to crates.io | ✅ Ready |
| **nightly.yml** | Daily at 2 AM UTC | Nightly builds, Miri, benchmarks | ✅ Ready |
| **dependencies.yml** | Weekly (Mondays) | Dependency updates & audits | ✅ Ready |

### CI Workflow Details

**Test Matrix:**
- Operating Systems: Ubuntu, Windows, macOS
- Rust Versions: stable, beta, nightly, 1.91.0 (MSRV)
- Features tested: all-features, no-default, individual features

**Quality Checks:**
- ✅ Clippy with `-D warnings` (zero warnings enforced)
- ✅ Rustfmt (code formatting)
- ✅ Documentation build
- ✅ Code coverage (tarpaulin → Codecov)
- ✅ Security audit (cargo-audit)
- ✅ Minimal versions check

### Publish Workflow Steps

1. **Trigger:** Push git tag matching `v*.*.*` pattern
2. **Version Check:** Verifies tag matches Cargo.toml version
3. **Tests:** Full test suite must pass
4. **Build:** Release build verification
5. **Package:** Create crate package
6. **Publish:** Upload to crates.io using `CARGO_REGISTRY_TOKEN`
   - Validates token is set before attempting publish
   - Uses `--allow-dirty` flag to handle generated files
   - Fails with clear error message if token is missing
7. **Release:** Create GitHub Release with auto-generated notes

## Required Secrets

### CARGO_REGISTRY_TOKEN

**Where to get it:**
1. Visit https://crates.io/settings/tokens
2. Click "New Token"
3. Name: "GitHub Actions - cardano-crypto"
4. Scope: "publish-update" (default)
5. Copy the generated token

**How to add to GitHub:**
1. Go to repository Settings
2. Navigate to Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `CARGO_REGISTRY_TOKEN`
5. Paste the token value
6. Click "Add secret"

**Environment variable name:** `CARGO_REGISTRY_TOKEN` (matches cardano-VRF)

**Important:** The workflow validates that this secret is set before attempting to publish. If the secret is missing or empty, the workflow will fail with a clear error message instead of attempting to run cargo publish with an empty token.

## Triggering Workflows

### Automatic Triggers

```bash
# CI runs on every push/PR to main
git push origin main

# Publish runs when you create a version tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# Nightly runs daily at 2 AM UTC (automatic)

# Dependencies runs weekly on Mondays (automatic)
```

### Manual Triggers

You can also trigger workflows manually from GitHub:
1. Go to Actions tab
2. Select the workflow
3. Click "Run workflow"
4. Choose branch and click "Run"

## Monitoring Workflows

### Check Status

```bash
# View all workflow runs
https://github.com/FractionEstate/Cardano-KES/actions

# Check specific workflow
https://github.com/FractionEstate/Cardano-KES/actions/workflows/ci.yml
```

### Status Badges

Add to README:
```markdown
[![CI](https://github.com/FractionEstate/Cardano-KES/workflows/CI/badge.svg)](https://github.com/FractionEstate/Cardano-KES/actions)
```

## Workflow Files Location

```
.github/
└── workflows/
    ├── ci.yml            # Main CI pipeline
    ├── publish.yml       # Crates.io publishing
    ├── nightly.yml       # Nightly builds
    └── dependencies.yml  # Dependency management
```

## Common Issues

### "Authentication token is invalid"
**Problem:** CARGO_REGISTRY_TOKEN is missing or expired
**Solution:**
1. Generate new token at https://crates.io/settings/tokens
2. Update GitHub secret

### "version already uploaded"
**Problem:** Trying to publish same version twice
**Solution:**
1. Bump version in Cargo.toml
2. Create new git tag

### "some files are not tracked by git"
**Problem:** Uncommitted changes
**Solution:**
1. Commit all changes
2. Or use `--allow-dirty` flag for testing

## Publishing Checklist

- [ ] All tests passing locally
- [ ] Zero compiler warnings
- [ ] Zero clippy warnings
- [ ] Documentation builds
- [ ] CHANGELOG.md updated
- [ ] Cargo.toml version bumped
- [ ] `CARGO_REGISTRY_TOKEN` secret configured in GitHub
- [ ] Changes committed to git
- [ ] Git tag created and pushed

## Release Command Reference

```bash
# Pre-release checks
cargo test --all-features
cargo clippy --all-targets --all-features
cargo doc --all-features --no-deps
cargo package --allow-dirty

# Commit and tag
git add .
git commit -m "chore: release v0.1.0"
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin main
git push origin v0.1.0

# GitHub Actions automatically:
# - Runs all tests
# - Publishes to crates.io
# - Creates GitHub Release
```

## Post-Release Verification

```bash
# Check crates.io
open https://crates.io/crates/cardano-crypto

# Check documentation
open https://docs.rs/cardano-crypto

# Test installation
cargo install cardano-crypto --dry-run
```

## Support

- Issues: https://github.com/FractionEstate/Cardano-KES/issues
- Discussions: https://github.com/FractionEstate/Cardano-KES/discussions
- Email: contact@fractionestate.io
