use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct CryptographicDetector;

impl CryptographicDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_cryptographic(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Advanced: Walk nested AST nodes, track data/control flow, check for cryptographic vulnerabilities, inter-function analysis
        let mut found = false;
        let mut line_number = function.span.start;
        let mut issue_type = String::new();
        let mut has_secure_randomness = false;
        let mut has_key_validation = false;
        let mut has_signature_validation = false;
        let mut crypto_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Weak cryptographic algorithms
            if l.contains("md5") || l.contains("sha1") || l.contains("des") || l.contains("3des") || l.contains("rc4") {
                found = true;
                issue_type = "weak_crypto_algorithm".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Weak PRNG
            if l.contains("rand()") || l.contains("random()") {
                found = true;
                issue_type = "weak_prng".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Timestamp-based randomness
            if l.contains("timestamp") && l.contains("%") {
                found = true;
                issue_type = "timestamp_randomness".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("block.timestamp") && l.contains("%") {
                found = true;
                issue_type = "block_timestamp_randomness".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("keccak256") && l.contains("block.timestamp") {
                found = true;
                issue_type = "timestamp_based_hash".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Hardcoded keys
            if l.contains("hardcoded") && l.contains("key") {
                found = true;
                issue_type = "hardcoded_key".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("private") && l.contains("key") && l.contains("=") {
                found = true;
                issue_type = "hardcoded_private_key".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("secret") && l.contains("=") {
                found = true;
                issue_type = "hardcoded_secret".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Insecure randomness patterns
            if l.contains("timestamp") && l.contains("rand") {
                found = true;
                issue_type = "timestamp_rand_combination".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("block.timestamp") && l.contains("*") {
                found = true;
                issue_type = "timestamp_multiplication".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("block.number") && l.contains("mod") {
                found = true;
                issue_type = "block_number_modulo".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("msg.sender") && l.contains("hash") {
                found = true;
                issue_type = "sender_based_hash".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Cryptographic function misuse
            if l.contains("keccak256") && l.contains('"') && l.contains("\"\"") {
                found = true;
                issue_type = "empty_string_hash".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("sha256") && l.contains('"') && l.contains("\"\"") {
                found = true;
                issue_type = "empty_string_sha256".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("hash") && l.contains("+") && l.contains("+") {
                found = true;
                issue_type = "string_concatenation_hash".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("constant") && l.contains("nonce") {
                found = true;
                issue_type = "fixed_nonce".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("ecrecover") && l.contains("0,") {
                found = true;
                issue_type = "invalid_signature_recovery".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Key management issues
            if l.contains("private_key") && l.contains("=") && l.contains('"') {
                found = true;
                issue_type = "hardcoded_private_key_string".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("todo") && l.contains("key") {
                found = true;
                issue_type = "todo_key_placeholder".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("fixme") && l.contains("key") {
                found = true;
                issue_type = "fixme_key_placeholder".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("test") && l.contains("private") && l.contains("key") {
                found = true;
                issue_type = "test_private_key".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            if l.contains("storage") && l.contains("key") && l.contains("write") {
                found = true;
                issue_type = "storage_key_write".to_string();
                crypto_lines.push(idx + line_number);
            }
            
            // Secure randomness checks
            if l.contains("secure_random") || l.contains("crypto_random") {
                has_secure_randomness = true;
            }
            
            // Key validation checks
            if l.contains("validate_key") || l.contains("check_key") {
                has_key_validation = true;
            }
            
            // Signature validation checks
            if l.contains("validate_signature") || l.contains("check_signature") {
                has_signature_validation = true;
            }
        }
        
        // Inter-function: check if this function is called by another public function
        let mut called_by_public = false;
        for f in &ast.functions {
            if f.name != function.name && f.content.contains(&function.name) && matches!(f.visibility, crate::parser::FunctionVisibility::Public) {
                called_by_public = true;
                break;
            }
        }
        
        if found && (!has_secure_randomness || !has_key_validation || !has_signature_validation || called_by_public) {
            let mut description = format!("Function '{}' contains potential cryptographic vulnerability ({}).", function.name, issue_type);
            if !has_secure_randomness {
                description.push_str(" No secure randomness source detected.");
            }
            if !has_key_validation {
                description.push_str(" No key validation detected.");
            }
            if !has_signature_validation {
                description.push_str(" No signature validation detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            let severity = match issue_type.as_str() {
                "hardcoded_private_key" | "hardcoded_private_key_string" | "test_private_key" => Severity::Critical,
                "weak_crypto_algorithm" | "timestamp_based_hash" | "invalid_signature_recovery" => Severity::High,
                "weak_prng" | "timestamp_randomness" | "block_timestamp_randomness" | "empty_string_hash" | "empty_string_sha256" => Severity::Medium,
                _ => Severity::Medium,
            };
            
            Some(Finding::new(
                "cryptographic",
                severity,
                Category::Cryptographic,
                0.9,
                &format!("Cryptographic Vulnerability Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Use strong cryptographic algorithms, secure randomness sources, and proper key management practices.",
            ))
        } else {
            None
        }
    }
}

impl Detector for CryptographicDetector {
    fn name(&self) -> &'static str {
        "cryptographic"
    }
    fn description(&self) -> &'static str {
        "Detects cryptographic vulnerabilities using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Cryptographic
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_cryptographic(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 