# SwayScanner

[![Crates.io](https://img.shields.io/crates/v/swayscan.svg)](https://crates.io/crates/swayscan)
[![Documentation](https://docs.rs/swayscan/badge.svg)](https://docs.rs/swayscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/Safe-Edges/swayscan/workflows/CI/badge.svg)](https://github.com/Safe-Edges/swayscan/actions)

**Advanced security scanner for Sway smart contracts with comprehensive vulnerability detection and minimal false positives.**

SwayScanner performs deep static analysis on Sway smart contracts to identify security vulnerabilities, code quality issues, and best practice violations. Built by the **Safe Edges Team** to secure the decentralized future.

## 🚀 Features

- **Comprehensive Security Analysis**: Detects 14+ categories of vulnerabilities including reentrancy, access control issues, oracle manipulation, and more
- **Professional Reports**: Export findings as beautifully formatted Markdown or PDF audit reports
- **Forc Plugin Support**: Seamlessly integrates with Forc workflow (`forc swayscan`)
- **Minimal False Positives**: Advanced analysis techniques reduce noise and focus on real issues
- **Grouped Findings**: Similar issues are intelligently grouped for better readability
- **Colored Output**: Professional terminal output with severity-based color coding
- **Multiple Output Formats**: Text, JSON, SARIF, CSV, and Markdown support
- **Safe Edges Branding**: Professional audit reports with Safe Edges branding

## 📦 Installation

### From crates.io (Recommended)

```bash
cargo install swayscan
```

### As Forc Plugin

SwayScanner automatically installs as a Forc plugin when installed via cargo:

```bash
cargo install swayscan
forc swayscan --version  # Verify installation
```

### From Source

```bash
git clone https://github.com/Safe-Edges/swayscan
cd swayscan
cargo install --path .
```

## 🔧 Usage

### Basic Usage

```bash
# Scan a single file
swayscan contract.sw

# Scan entire Forc project
forc swayscan

# Scan with Markdown report (recommended)
swayscan contract.sw --export-md

# Scan all Sway files recursively  
swayscan --scan-all
```

### Professional Audit Reports

```bash
# Generate comprehensive Markdown audit report
swayscan contract.sw --markdown-report audit-report.md

# Multiple output formats
swayscan contract.sw --display-format json
swayscan contract.sw --display-format sarif
```

### Advanced Options

```bash
# Scan with specific detectors only
swayscan contract.sw --detectors access_control,reentrancy

# Exclude specific detectors
swayscan contract.sw --exclude-detectors magic_number

# Filter by severity
swayscan contract.sw --severity-filter high

# Verbose output with detailed analysis
swayscan contract.sw --verbose

# Set confidence threshold
swayscan contract.sw --confidence-threshold 0.8
```

### Forc Plugin Usage

When using as a Forc plugin, SwayScanner automatically detects your project structure:

```bash
# Navigate to any Forc project
cd my-sway-project

# Run security analysis
forc swayscan

# Generate audit report
forc swayscan --markdown-report security-audit.md

# Scan with high severity findings only
forc swayscan --severity-filter high --fail-on high
```

## 🛡️ Vulnerability Detection

SwayScanner detects the following vulnerability categories:

### Critical & High Severity
- **Access Control**: Missing or inadequate permission checks
- **Reentrancy**: Vulnerable external call patterns
- **Arithmetic Issues**: Integer overflow/underflow and division errors
- **Business Logic**: Complex logic flaws and validation issues
- **Price Oracle Manipulation**: Single oracle dependencies and flash loan vulnerabilities
- **Flash Loan Attacks**: Atomic transaction exploits
- **External Call Safety**: Unchecked external calls and return values
- **UTXO Vulnerabilities**: Fuel-specific UTXO model security issues

### Medium Severity
- **Logic Errors**: Off-by-one errors and assignment vs comparison bugs
- **Input Validation**: Parameter validation and bounds checking
- **Unprotected Storage**: Storage modifications without access restrictions

### Low Severity  
- **Code Quality**: Unused variables, imports, and dead code
- **Best Practices**: Magic numbers and coding standard violations

## 📋 Example Output

```
================================================================================

    ███████╗██╗    ██╗ █████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████╗██║ █╗ ██║███████║ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ╚════██║██║███╗██║██╔══██║  ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ███████║╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

        Comprehensive Security Analysis for Sway Smart Contracts
                           Powered by Safe Edges
                          https://safeedges.in
================================================================================

Running detectors... (14 active)

SECURITY AUDIT REPORT
===========================================

CRITICAL: access_control
├─ Missing access control in admin_mint function
├─ Location: contract.sw:45:5
└─ Risk: Unauthorized users can mint tokens

HIGH: reentrancy  
├─ Potential reentrancy in unsafe_withdraw function
├─ Location: contract.sw:67:5
└─ Risk: Attacker can drain contract funds

MEDIUM: input_validation
├─ Missing input validation in transfer function  
├─ Location: contract.sw:23:5
└─ Risk: Invalid parameters may cause unexpected behavior
```

## 📚 Examples

Check out the `examples/` directory for sample vulnerable contracts to test SwayScanner:

```bash
# Test on example vulnerable contract
swayscan examples/vulnerable_contract.sw --export-md
```

## 🔧 Configuration

Create a `swayscan.toml` configuration file for custom settings:

```toml
[analysis]
confidence_threshold = 0.7
parallel_threads = 4

[detectors]
enabled = ["access_control", "reentrancy", "arithmetic_issues"]
disabled = ["magic_number"]

[output]
format = "text"
color = true
```

## 📖 Documentation

- **API Documentation**: [docs.rs/swayscan](https://docs.rs/swayscan)
- **Repository**: [github.com/Safe-Edges/swayscan](https://github.com/Safe-Edges/swayscan)
- **Website**: [safeedges.in](https://safeedges.in)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ About Safe Edges

SwayScanner is developed by **Safe Edges**, a team dedicated to securing the decentralized future through advanced security tooling and auditing services.

- **Website**: [https://safeedges.in](https://safeedges.in)
- **Email**: info@safeedges.in
- **GitHub**: [Safe-Edges](https://github.com/Safe-Edges)

---

**Made with ❤️ by the Safe Edges Team** 
 