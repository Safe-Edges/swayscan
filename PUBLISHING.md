# SwayScanner - crates.io Publishing Guide

This document outlines the steps for publishing SwayScanner to crates.io.

## ✅ Pre-Publishing Checklist

### Directory Structure ✅
- [x] Cleaned up debug/test files
- [x] Moved example files to `examples/` directory
- [x] Created proper Rust integration tests in `tests/`
- [x] Updated `.gitignore` with comprehensive patterns
- [x] Removed generated reports and temporary documentation

### Cargo.toml Configuration ✅
- [x] Updated description for crates.io
- [x] Added proper keywords and categories
- [x] Set minimum Rust version (1.70)
- [x] Added comprehensive exclude patterns
- [x] Verified license (MIT)
- [x] Added repository and homepage URLs

### Documentation ✅
- [x] Professional README.md with badges
- [x] Installation instructions
- [x] Usage examples
- [x] Feature descriptions
- [x] API documentation references
- [x] Safe Edges branding

### Code Quality ✅
- [x] Project compiles without errors
- [x] Integration tests pass
- [x] Professional ASCII welcome banner
- [x] Markdown export recommendations

## 📦 Final Project Structure

```
swayscan/
├── src/                    # Source code
├── examples/               # Example vulnerable contracts
│   ├── vulnerable_contract.sw
│   ├── test_reentrancy.sw
│   └── test_access_control.sw
├── tests/                  # Rust integration tests
│   └── integration_tests.rs
├── Cargo.toml             # Crate metadata
├── README.md              # Main documentation
├── .gitignore            # Git ignore patterns
└── PUBLISHING.md         # This file
```

## 🚀 Publishing Steps

### 1. Final Testing
```bash
# Ensure everything builds
cargo check

# Run tests
cargo test

# Test the CLI
cargo run --bin swayscan -- --files examples/vulnerable_contract.sw

# Test as Forc plugin
cargo run --bin forc-swayscan -- examples/vulnerable_contract.sw
```

### 2. Version Management
Update version in `Cargo.toml` if needed:
```toml
version = "0.2.1"  # Current version
```

### 3. Login to crates.io
```bash
cargo login
# Enter your API token from https://crates.io/me
```

### 4. Dry Run
```bash
cargo publish --dry-run
```

### 5. Publish
```bash
cargo publish
```

## 📋 Post-Publishing Tasks

### Immediate
- [ ] Verify package appears on crates.io
- [ ] Test installation: `cargo install swayscan`
- [ ] Update GitHub repository with release tag
- [ ] Update Safe Edges website

### Documentation
- [ ] Update docs.rs with API documentation
- [ ] Create GitHub release with changelog
- [ ] Update any external documentation links

### Community
- [ ] Announce on Fuel community channels
- [ ] Share on social media
- [ ] Update Safe Edges portfolio

## 🔄 Future Releases

For future releases:

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md (if created)
3. Run full test suite
4. Execute publishing steps above

## 🛡️ Safe Edges Branding

SwayScanner is published under the Safe Edges brand:
- **Publisher**: Safe Edges Team <info@safeedges.in>
- **Website**: https://safeedges.in
- **License**: MIT
- **Repository**: https://github.com/Safe-Edges/swayscan

## 📞 Support

For publishing issues or questions:
- Email: info@safeedges.in
- GitHub Issues: https://github.com/Safe-Edges/swayscan/issues

---

**Ready for crates.io publication!** 🚀 