# SwayScanner

[![Crates.io](https://img.shields.io/crates/v/swayscan.svg)](https://crates.io/crates/swayscan)
[![Documentation](https://docs.rs/swayscan/badge.svg)](https://docs.rs/swayscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/Safe-Edges/swayscan/workflows/CI/badge.svg)](https://github.com/Safe-Edges/swayscan/actions)

**Advanced AST-based security scanner for Sway smart contracts with comprehensive vulnerability detection and minimal false positives.**

SwayScanner performs deep **AST-based static analysis** on Sway smart contracts to identify security vulnerabilities, code quality issues, and best practice violations. Built by the **Safe Edges Team** to secure the decentralized future.

##  Features

- **AST-Based Analysis**: Uses Sway language AST for accurate parsing and analysis
- **Comprehensive Security Analysis**: Detects 14+ categories of vulnerabilities including reentrancy, access control issues, oracle manipulation, and more
- **Professional Reports**: Export findings as beautifully formatted Markdown or PDF audit reports
- **Minimal False Positives**: Advanced AST analysis techniques reduce noise and focus on real issues
- **Grouped Findings**: Similar issues are intelligently grouped for better readability
- **Colored Output**: Professional terminal output with severity-based color coding
- **Multiple Output Formats**: Text, JSON, SARIF, CSV, and Markdown support
- **Safe Edges Branding**: Professional audit reports with Safe Edges branding

## 🔧 Technical Architecture

### AST-Based Analysis Engine
- **Sway AST Parser**: Uses official Sway language AST for accurate code understanding
- **Function Call Graph**: Maps function relationships and call chains
- **Storage Analysis**: Tracks storage read/write operations
- **Control Flow Analysis**: Analyzes conditional branches and loops
- **Security Analysis**: Performs vulnerability detection using AST patterns

### Key Components
- **SwayAstAnalyzer**: Main analysis engine using Sway AST
- **FunctionCallGraph**: Maps caller-callee relationships
- **StorageAnalysis**: Tracks storage operations and dependencies
- **ControlFlowAnalysis**: Analyzes program flow and control structures
- **SecurityAnalysis**: Detects security vulnerabilities using AST patterns

## 📦 Installation

### From crates.io (Recommended)

```bash
cargo install swayscan
```


```bash
cargo install swayscan
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
# Scan a single file with AST-based analysis
swayscan contract.sw

swayscan contract.sw -d path

# Scan with Markdown report (recommended)
swayscan contract.sw -o name.md

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

# Verbose output with detailed AST analysis
swayscan contract.sw --verbose

```

##  Vulnerability Detection

SwayScanner uses AST-based analysis to detect the following vulnerability categories:

### Critical & High Severity
- **Access Control**: Missing or inadequate permission checks using AST function analysis
- **Reentrancy**: Vulnerable external call patterns detected through AST call graphs
- **Arithmetic Issues**: Integer overflow/underflow and division errors using AST expression analysis
- **Business Logic**: Complex logic flaws and validation issues through AST control flow analysis
- **Price Oracle Manipulation**: Single oracle dependencies and flash loan vulnerabilities
- **Flash Loan Attacks**: Atomic transaction exploits detected via AST
- **External Call Safety**: Unchecked external calls and return values using AST call analysis
- **UTXO Vulnerabilities**: Fuel-specific UTXO model security issues

### Medium Severity
- **Logic Errors**: Off-by-one errors and assignment vs comparison bugs
- **Input Validation**: Parameter validation and bounds checking
- **Unprotected Storage**: Storage modifications without access restrictions

### Low Severity  
- **Code Quality**: Unused variables, imports, and dead code
- **Best Practices**: Magic numbers and coding standard violations

##  Example Output

```
================================================================================

    ███████╗██╗    ██╗ █████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████╗██║ █╗ ██║███████║ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
    ╚════██║██║███╗██║██╔══██║  ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
    ███████║╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

        AST-Based Security Analysis for Sway Smart Contracts
                           Powered by Safe Edges
                          https://safeedges.in
================================================================================

Running AST-based detectors... (14 active)

SECURITY AUDIT REPORT
===========================================

CRITICAL: access_control
├─ Missing access control in admin_mint function
├─ Location: contract.sw:45:5 (AST span: 45:5-67:8)
└─ Risk: Unauthorized users can mint tokens

HIGH: reentrancy  
├─ Potential reentrancy in unsafe_withdraw function
├─ Location: contract.sw:67:5 (AST span: 67:5-89:12)
└─ Risk: Attacker can drain contract funds

MEDIUM: input_validation
├─ Missing input validation in transfer function  
├─ Location: contract.sw:23:5 (AST span: 23:5-45:10)
└─ Risk: Invalid parameters may cause unexpected behavior
```

##  Examples

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
ast_analysis = true

[detectors]
enabled = ["access_control", "reentrancy", "arithmetic_issues"]
disabled = ["magic_number"]

[output]
format = "text"
color = true
```

##  Documentation

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

**Made by the Safe Edges Team** 
 
