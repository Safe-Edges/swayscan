use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct UncheckedExternalCallDetector;

// External call patterns in Sway
static EXTERNAL_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"abi\([^)]+\)\.[\w]+\([^)]*\);").unwrap(), // ABI calls without assignment
        Regex::new(r"contract_call\s*\([^)]*\);").unwrap(), // Contract calls without checking
        Regex::new(r"transfer\s*\([^)]*\);").unwrap(), // Transfer without checking
        Regex::new(r"force_transfer_to_contract\s*\([^)]*\);").unwrap(), // Force transfer
        Regex::new(r"mint_to\s*\([^)]*\);").unwrap(), // Mint without checking
        Regex::new(r"burn\s*\([^)]*\);").unwrap(), // Burn without checking
    ]
});

// Checked external call patterns (good)
static CHECKED_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"let\s+\w+\s*=\s*abi\([^)]+\)\.[\w]+\([^)]*\)").unwrap(), // Assigned result
        Regex::new(r"match\s+abi\([^)]+\)\.[\w]+\([^)]*\)").unwrap(), // Match on result
        Regex::new(r"if\s+let\s+\w+\s*=\s*abi").unwrap(), // If let pattern
        Regex::new(r"\.is_ok\(\)").unwrap(), // Checking if result is ok
        Regex::new(r"\.unwrap_or").unwrap(), // Handling with unwrap_or
        Regex::new(r"\.expect\(").unwrap(), // Using expect for errors
    ]
});

// Error handling patterns
static ERROR_HANDLING_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(").unwrap(),
        Regex::new(r"assert\s*\(").unwrap(),
        Regex::new(r"revert\s*\(").unwrap(),
        Regex::new(r"Result<").unwrap(),
        Regex::new(r"Option<").unwrap(),
        Regex::new(r"match\s+").unwrap(),
    ]
});

// High-risk call types
static HIGH_RISK_CALLS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)transfer\s*\(").unwrap(),
        Regex::new(r"(?i)send\s*\(").unwrap(),
        Regex::new(r"(?i)call\s*\(").unwrap(),
        Regex::new(r"(?i)delegatecall\s*\(").unwrap(),
        Regex::new(r"(?i)staticcall\s*\(").unwrap(),
        Regex::new(r"(?i)mint\s*\(").unwrap(),
        Regex::new(r"(?i)burn\s*\(").unwrap(),
        Regex::new(r"(?i)liquidate\s*\(").unwrap(),
    ]
});

impl UncheckedExternalCallDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_unchecked_external_calls(&self, content: &str) -> Vec<(usize, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            // Skip if already properly checked
            if self.is_call_checked(line, &lines, i) {
                continue;
            }
            
            for pattern in EXTERNAL_CALL_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    let call_type = self.determine_call_type(line);
                    findings.push((i + 1, mat.as_str().to_string(), call_type));
                }
            }
        }
        findings
    }

    fn is_call_checked(&self, line: &str, lines: &[&str], line_index: usize) -> bool {
        // Check if the call itself has error handling
        for pattern in CHECKED_CALL_PATTERNS.iter() {
            if pattern.is_match(line) {
                return true;
            }
        }
        
        // Check surrounding lines for error handling
        let start = line_index.saturating_sub(2);
        let end = (line_index + 3).min(lines.len());
        
        for i in start..end {
            if i < lines.len() {
                for pattern in ERROR_HANDLING_PATTERNS.iter() {
                    if pattern.is_match(lines[i]) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn determine_call_type(&self, line: &str) -> String {
        if line.contains("transfer") {
            "transfer".to_string()
        } else if line.contains("mint") {
            "mint".to_string()
        } else if line.contains("burn") {
            "burn".to_string()
        } else if line.contains("contract_call") {
            "contract_call".to_string()
        } else if line.contains("abi(") {
            "abi_call".to_string()
        } else {
            "external_call".to_string()
        }
    }

    fn is_high_risk_call(&self, line: &str) -> bool {
        for pattern in HIGH_RISK_CALLS.iter() {
            if pattern.is_match(line) {
                return true;
            }
        }
        false
    }

    fn extract_function_context(&self, content: &str, line_num: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut start = line_num.saturating_sub(1);
        
        // Find function start
        while start > 0 {
            if lines[start].trim().starts_with("fn ") || lines[start].trim().starts_with("pub fn ") {
                break;
            }
            start -= 1;
        }
        
        // Get function content
        let end = (start + 30).min(lines.len());
        lines[start..end].join("\n")
    }

    fn calculate_risk_score(&self, line: &str, call_type: &str, function_content: &str) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk for unchecked external call
        risk_score += 0.6;
        
        // Higher risk for specific call types
        match call_type {
            "transfer" | "mint" | "burn" => risk_score += 0.3,
            "contract_call" => risk_score += 0.2,
            "abi_call" => risk_score += 0.15,
            _ => risk_score += 0.1,
        }
        
        // Higher risk if high-risk operation
        if self.is_high_risk_call(line) {
            risk_score += 0.2;
        }
        
        // Higher risk in financial functions
        if function_content.contains("balance") || function_content.contains("amount") || 
           function_content.contains("fee") || function_content.contains("reward") {
            risk_score += 0.2;
        }
        
        // Higher risk if in loops (can cause out-of-gas)
        if function_content.contains("for ") || function_content.contains("while ") {
            risk_score += 0.15;
        }
        
        // Reduce risk if some error handling exists elsewhere in function
        let error_handling_count = ERROR_HANDLING_PATTERNS.iter()
            .filter(|pattern| pattern.is_match(function_content))
            .count();
        
        if error_handling_count >= 2 {
            risk_score *= 0.7;
        } else if error_handling_count == 1 {
            risk_score *= 0.9;
        }
        
        risk_score.min(1.0)
    }
}

impl Detector for UncheckedExternalCallDetector {
    fn name(&self) -> &'static str {
        "unchecked_external_calls"
    }
    
    fn description(&self) -> &'static str {
        "Detects external calls that don't properly handle return values or potential failures"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find unchecked external calls
        let unchecked_calls = self.find_unchecked_external_calls(&file.content);
        
        for (line_num, call_pattern, call_type) in unchecked_calls {
            let line = file.content.lines().nth(line_num - 1).unwrap_or("");
            let function_content = self.extract_function_context(&file.content, line_num);
            
            let confidence = self.calculate_risk_score(line, &call_type, &function_content);
            
            if confidence >= 0.7 {
                let severity = if confidence >= 0.9 {
                    Severity::High
                } else if confidence >= 0.8 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let mut risk_factors = Vec::new();
                if self.is_high_risk_call(line) {
                    risk_factors.push("High-risk financial operation");
                }
                if function_content.contains("for ") || function_content.contains("while ") {
                    risk_factors.push("Called within loop (DoS risk)");
                }
                if function_content.contains("balance") || function_content.contains("amount") {
                    risk_factors.push("Financial context");
                }

                let call_description = match call_type.as_str() {
                    "transfer" => "Asset transfer",
                    "mint" => "Token minting",
                    "burn" => "Token burning",
                    "contract_call" => "Contract call",
                    "abi_call" => "ABI call",
                    _ => "External call",
                };

                let finding = Finding::new(
                    self.name(),
                    severity,
                    self.category(),
                    confidence,
                    "Unchecked External Call",
                    &format!(
                        "{} at line {} does not check return value or handle potential failures. Call: '{}'. Risk factors: {}. Failed external calls can cause unexpected behavior or loss of funds.",
                        call_description,
                        line_num,
                        call_pattern.trim(),
                        if risk_factors.is_empty() { "None identified".to_string() } else { risk_factors.join(", ") }
                    ),
                    &file.path,
                    line_num,
                    1,
                    extract_code_snippet(&file.content, line_num, 2),
                    &format!(
                        "Handle external call results properly: (1) Assign return value and check for success, (2) Use match statement for Result types, (3) Add require() or assert() for critical calls, (4) Consider using try-catch equivalent patterns. Example: let result = {}; require(result.is_ok(), \"Call failed\");",
                        match call_type.as_str() {
                            "abi_call" => "abi(...).function(...)",
                            "transfer" => "transfer(...)",
                            _ => "external_call(...)"
                        }
                    ),
                )
                .with_impact("Medium to High - Unchecked external calls can lead to silent failures, unexpected state, or loss of funds")
                .with_effort(EstimatedEffort::Easy)
                .with_cwe(vec![252, 754, 703]) // CWE-252: Unchecked Return Value, CWE-754: Improper Check for Unusual Conditions, CWE-703: Improper Check or Handling of Exceptional Conditions
                .with_references(vec![
                    Reference {
                        title: "Sway External Calls".to_string(),
                        url: "https://docs.fuel.network/docs/sway/advanced/external-calls/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    },
                    Reference {
                        title: "SWC-104: Unchecked Call Return Value".to_string(),
                        url: "https://swcregistry.io/docs/SWC-104".to_string(),
                        reference_type: ReferenceType::Standard,
                    }
                ])
                .with_context(context.clone());
                
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }
} 