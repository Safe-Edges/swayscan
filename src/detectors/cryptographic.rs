use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct CryptographicDetector;

// Weak cryptographic patterns
static WEAK_CRYPTO_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)md5|sha1|des|3des|rc4").unwrap(), // Weak hash functions and ciphers
        Regex::new(r"rand\(\)|random\(\)").unwrap(), // Weak PRNG
        Regex::new(r"timestamp\s*%|block\.timestamp\s*%").unwrap(), // Timestamp as randomness
        Regex::new(r"block\.number\s*%").unwrap(), // Block number as randomness
        Regex::new(r"keccak256\(block\.timestamp\)").unwrap(), // Timestamp-based randomness
        Regex::new(r"(?i)hardcoded.*key|private.*key.*=|secret.*=").unwrap(), // Hardcoded keys
    ]
});

// Insecure randomness patterns
static INSECURE_RANDOMNESS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"timestamp.*rand|rand.*timestamp").unwrap(),
        Regex::new(r"block\.timestamp\s*\*\s*\d+").unwrap(),
        Regex::new(r"block\.number.*mod|mod.*block\.number").unwrap(),
        Regex::new(r"msg\.sender.*hash|hash.*msg\.sender").unwrap(),
        Regex::new(r"(?i)predictable.*seed|weak.*seed").unwrap(),
    ]
});

// Cryptographic function misuse
static CRYPTO_MISUSE: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"keccak256\(\s*""|sha256\(\s*"""#).unwrap(), // Empty string hashing
        Regex::new(r"hash\(.*\+.*\+.*\)").unwrap(), // String concatenation before hashing
        Regex::new(r"(?i)constant.*nonce|fixed.*nonce").unwrap(), // Fixed nonces
        Regex::new(r"ecrecover\s*\([^)]*,\s*0\s*,").unwrap(), // Invalid signature recovery
    ]
});

// Key management issues
static KEY_MANAGEMENT_ISSUES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"private_key\s*=\s*"[^"]+""#).unwrap(), // Hardcoded private keys
        Regex::new(r"(?i)todo.*key|fixme.*key").unwrap(), // TODO/FIXME for keys
        Regex::new(r"(?i)test.*private.*key|example.*key").unwrap(), // Test keys in production
        Regex::new(r"storage\..*key.*\.write").unwrap(), // Storing keys in storage
    ]
});

impl CryptographicDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_weak_crypto(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for weak cryptographic algorithms
            for pattern in WEAK_CRYPTO_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let confidence = if line.contains("md5") || line.contains("sha1") {
                        0.95 // Very high confidence for known weak algorithms
                    } else if line.contains("timestamp") && line.contains("%") {
                        0.85 // High confidence for timestamp-based randomness
                    } else {
                        0.75
                    };

                    let severity = if line.contains("private") || line.contains("key") {
                        Severity::Critical
                    } else if line.contains("md5") || line.contains("sha1") {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    findings.push(
                        Finding::new(
                            self.name(),
                            severity,
                            Category::Security,
                            confidence,
                            "Weak Cryptographic Implementation",
                            &format!(
                                "Detected use of weak cryptographic algorithm or insecure randomness source: {}",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Use strong cryptographic algorithms (SHA-256, SHA-3) and secure randomness sources. Avoid predictable inputs for cryptographic operations.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![327, 338, 330]) // Use of Broken Crypto, Weak PRNG, Insufficient Randomness
                        .with_references(vec![
                            Reference {
                                title: "OWASP Cryptographic Storage Cheat Sheet".to_string(),
                                url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html".to_string(),
                                reference_type: ReferenceType::Security,
                            },
                        ])
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }

            // Check for insecure randomness
            for pattern in INSECURE_RANDOMNESS.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::High,
                            Category::Security,
                            0.85,
                            "Insecure Randomness Source",
                            &format!(
                                "Using predictable or weak randomness source: {}. This can lead to predictable outcomes in security-critical operations.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Use a cryptographically secure random number generator (CSPRNG) or commit-reveal schemes for randomness in smart contracts.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![338, 330])
                        .with_effort(EstimatedEffort::Hard)
                    );
                }
            }

            // Check for cryptographic function misuse
            for pattern in CRYPTO_MISUSE.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Medium,
                            Category::Security,
                            0.8,
                            "Cryptographic Function Misuse",
                            &format!(
                                "Potential misuse of cryptographic function: {}. This may lead to weak or predictable cryptographic operations.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Follow cryptographic best practices: use proper input validation, avoid empty inputs, use unique nonces, and validate signature recovery parameters.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![327, 345])
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }

            // Check for key management issues
            for pattern in KEY_MANAGEMENT_ISSUES.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Critical,
                            Category::Security,
                            0.9,
                            "Key Management Vulnerability",
                            &format!(
                                "Critical key management issue detected: {}. Private keys should never be hardcoded or stored insecurely.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Implement secure key management: use environment variables, hardware security modules (HSMs), or secure key derivation functions. Never hardcode private keys.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![798, 321]) // Hardcoded Credentials, Use of Hard-coded Cryptographic Key
                        .with_effort(EstimatedEffort::Expert)
                    );
                }
            }
        }

        findings
    }
}

impl Detector for CryptographicDetector {
    fn name(&self) -> &'static str {
        "cryptographic_issues"
    }
    
    fn description(&self) -> &'static str {
        "Detects cryptographic vulnerabilities including weak algorithms, insecure randomness, and key management issues"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Analyze weak cryptographic implementations
        all_findings.extend(self.analyze_weak_crypto(file, context));
        
        Ok(all_findings)
    }
} 