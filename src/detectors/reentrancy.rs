use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct ReentrancyDetector;

// Patterns for external calls in Sway
static EXTERNAL_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?m)^\s*let\s+\w+\s*=\s*abi\([^)]+\)\s*\.").unwrap(), // ABI calls
        Regex::new(r"(?m)contract_call\s*\(").unwrap(), // Direct contract calls
        Regex::new(r"(?m)transfer\s*\(").unwrap(), // Asset transfers
        Regex::new(r"(?m)force_transfer_to_contract\s*\(").unwrap(), // Force transfers
        Regex::new(r"(?m)mint_to\s*\(").unwrap(), // Minting operations
        Regex::new(r"(?m)burn\s*\(").unwrap(), // Burn operations
    ]
});

// Storage write patterns
static STORAGE_WRITE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.[\w\.]+\.write\s*\(").unwrap(),
        Regex::new(r"storage\.[\w\.]+\.insert\s*\(").unwrap(),
        Regex::new(r"storage\.[\w\.]+\.remove\s*\(").unwrap(),
        Regex::new(r"storage\.[\w\.]+\.push\s*\(").unwrap(),
        Regex::new(r"storage\.[\w\.]+\.pop\s*\(").unwrap(),
    ]
});

// State-changing function patterns
static STATE_CHANGE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"#\[storage\(read,\s*write\)\]").unwrap(),
        Regex::new(r"fn\s+\w+.*\{[^}]*storage\.[\w\.]+\.write").unwrap(),
    ]
});

// Reentrancy protection patterns
static PROTECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"nonReentrant").unwrap(),
        Regex::new(r"reentrancy_guard").unwrap(),
        Regex::new(r"mutex").unwrap(),
        Regex::new(r"locked").unwrap(),
        Regex::new(r"require\s*\(\s*![\w\.]*lock").unwrap(),
    ]
});

impl ReentrancyDetector {
    pub fn new() -> Self {
        Self
    }

    fn has_external_call(&self, content: &str) -> Vec<(usize, &str, String)> {
        let mut calls = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            for pattern in EXTERNAL_CALL_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    calls.push((i + 1, "external_call", mat.as_str().to_string()));
                }
            }
        }
        calls
    }

    fn has_storage_write_after(&self, content: &str, start_line: usize) -> Vec<(usize, String)> {
        let mut writes = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        // Look for storage writes in the same function after the external call
        for (i, line) in lines.iter().enumerate().skip(start_line.saturating_sub(1)) {
            for pattern in STORAGE_WRITE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    writes.push((i + 1, mat.as_str().to_string()));
                }
            }
            
            // Stop at function boundary
            if line.trim().starts_with("fn ") || line.trim() == "}" {
                break;
            }
        }
        writes
    }

    fn has_reentrancy_protection(&self, function_content: &str) -> bool {
        for pattern in PROTECTION_PATTERNS.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn extract_function_content(&self, content: &str, line_num: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut start = line_num.saturating_sub(1);
        let mut end = line_num;
        
        // Find function start
        while start > 0 {
            if lines[start].trim().starts_with("fn ") || lines[start].trim().starts_with("pub fn ") {
                break;
            }
            start -= 1;
        }
        
        // Find function end
        let mut brace_count = 0;
        let mut found_opening = false;
        for i in start..lines.len() {
            for ch in lines[i].chars() {
                match ch {
                    '{' => {
                        brace_count += 1;
                        found_opening = true;
                    },
                    '}' => {
                        brace_count -= 1;
                        if found_opening && brace_count == 0 {
                            end = i;
                            return lines[start..=end].join("\n");
                        }
                    },
                    _ => {}
                }
            }
        }
        
        lines[start..end.min(lines.len())].join("\n")
    }

    fn analyze_reentrancy_risk(&self, external_calls: &[(usize, &str, String)], storage_writes: &[(usize, String)], function_content: &str) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk for external call + storage write pattern
        if !external_calls.is_empty() && !storage_writes.is_empty() {
            risk_score += 0.6;
        }
        
        // Higher risk if storage write happens after external call
        for (call_line, _, _) in external_calls {
            for (write_line, _) in storage_writes {
                if write_line > call_line {
                    risk_score += 0.3;
                    break;
                }
            }
        }
        
        // Higher risk for financial operations
        if function_content.contains("transfer") || function_content.contains("mint") || function_content.contains("burn") {
            risk_score += 0.2;
        }
        
        // Reduce risk if protection is present
        if self.has_reentrancy_protection(function_content) {
            risk_score *= 0.3; // Significantly reduce if protection exists
        }
        
        // Cap at 1.0
        risk_score.min(1.0)
    }
}

impl Detector for ReentrancyDetector {
    fn name(&self) -> &'static str {
        "reentrancy_vulnerability"
    }
    
    fn description(&self) -> &'static str {
        "Detects potential reentrancy vulnerabilities in Sway contracts where external calls are followed by state changes"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Critical
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find all external calls
        let external_calls = self.has_external_call(&file.content);
        
        for (call_line, call_type, call_pattern) in external_calls {
            // Extract the function containing this call
            let function_content = self.extract_function_content(&file.content, call_line);
            
            // Look for storage writes after this external call
            let storage_writes = self.has_storage_write_after(&file.content, call_line);
            
            if !storage_writes.is_empty() {
                let confidence = self.analyze_reentrancy_risk(&[(call_line, call_type, call_pattern.clone())], &storage_writes, &function_content);
                
                // Only report if confidence is above threshold
                if confidence >= 0.7 {
                    let severity = if confidence >= 0.9 {
                        Severity::Critical
                    } else if confidence >= 0.8 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let storage_details: Vec<String> = storage_writes.iter()
                        .map(|(line, pattern)| format!("Line {}: {}", line, pattern))
                        .collect();

                    let finding = Finding::new(
                        self.name(),
                        severity,
                        self.category(),
                        confidence,
                        "Potential Reentrancy Vulnerability",
                        &format!(
                            "External call at line {} may allow reentrancy attack. State changes detected after external call: {}. This pattern can allow an attacker to call back into the contract before state changes are finalized.",
                            call_line,
                            storage_details.join(", ")
                        ),
                        &file.path,
                        call_line,
                        1,
                        extract_code_snippet(&file.content, call_line, 3),
                        "Implement the checks-effects-interactions pattern: (1) Perform all checks, (2) Make state changes, (3) Interact with external contracts. Consider using a reentrancy guard or mutex.",
                    )
                    .with_impact("Critical - Attackers can drain contract funds or manipulate state")
                    .with_effort(EstimatedEffort::Medium)
                    .with_cwe(vec![841, 362]) // CWE-841: Improper Enforcement of Behavioral Workflow, CWE-362: Race Condition
                    .with_references(vec![
                        Reference {
                            title: "Sway Security: Reentrancy Prevention".to_string(),
                            url: "https://docs.fuel.network/docs/sway/advanced/security/".to_string(),
                            reference_type: ReferenceType::Documentation,
                        },
                        Reference {
                            title: "SWC-107: Reentrancy".to_string(),
                            url: "https://swcregistry.io/docs/SWC-107".to_string(),
                            reference_type: ReferenceType::Standard,
                        }
                    ])
                    .with_context(context.clone());
                    
                    findings.push(finding);
                }
            }
        }
        
        Ok(findings)
    }
} 