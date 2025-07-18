use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct InputValidationDetector;

// Function parameters that need validation - more robust patterns
static RISKY_PARAMETER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*u\d+)[^)]*\)").unwrap(), // Unsigned integer parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*Identity)[^)]*\)").unwrap(), // Identity parameters  
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*Address)[^)]*\)").unwrap(), // Address parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*AssetId)[^)]*\)").unwrap(), // Asset ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*ContractId)[^)]*\)").unwrap(), // Contract ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*b256)[^)]*\)").unwrap(), // Hash parameters
    ]
});

// More comprehensive validation patterns
static VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*\w+\s*[><!]=?\s*\d+").unwrap(), // Boundary checks
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Address::zero\(\)").unwrap(), // Zero address checks
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Identity::Address\(Address::zero\(\)\)").unwrap(), // Identity zero checks
        Regex::new(r"require\s*\(\s*\w+\s*>\s*0").unwrap(), // Non-zero checks
        Regex::new(r"assert\s*\(\s*\w+").unwrap(), // Assert statements
        Regex::new(r"revert\s*\(").unwrap(), // Explicit reverts
        Regex::new(r"(?i)validate|check|verify").unwrap(), // Validation functions
        Regex::new(r"if\s+\w+\s*[<>=!]+\s*\d+\s*\{[^}]*revert").unwrap(), // Conditional reverts
    ]
});

// High-risk operations requiring validation
static HIGH_RISK_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\([^)]*amount").unwrap(), // Asset transfers with amount
        Regex::new(r"mint_to\s*\([^)]*amount").unwrap(), // Minting with amount
        Regex::new(r"burn\s*\([^)]*amount").unwrap(), // Burning with amount
        Regex::new(r"storage\.\w+\.write\s*\(\s*\w+").unwrap(), // Storage writes
        Regex::new(r"force_transfer_to_contract").unwrap(), // Force transfers
        Regex::new(r"approve\s*\([^)]*amount").unwrap(), // Approvals with amount
    ]
});

// Financial context patterns that increase risk
static FINANCIAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)balance|amount|price|value|fund|asset|token").unwrap(),
        Regex::new(r"(?i)withdraw|deposit|mint|burn|transfer|liquidate").unwrap(),
        Regex::new(r"(?i)collateral|debt|loan|interest|fee").unwrap(),
    ]
});

// Safe function patterns that don't need validation
static SAFE_FUNCTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)view|pure|get|read|query|balance_of|total_supply").unwrap(),
        Regex::new(r"(?i)info|status|metadata|config").unwrap(),
        Regex::new(r"fn\s+test_").unwrap(), // Test functions
        Regex::new(r"#\[test\]").unwrap(), // Test annotations
    ]
});

impl InputValidationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_parameters(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;

            // Skip safe functions
            if SAFE_FUNCTION_PATTERNS.iter().any(|p| p.is_match(line)) {
                continue;
            }

            // Check for risky function parameters
            for pattern in RISKY_PARAMETER_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let has_validation = self.has_comprehensive_validation(&lines, line_num);
                    let has_risky_ops = self.has_high_risk_operations(&lines, line_num);
                    let is_financial_context = self.is_financial_function(&lines, line_num);
                    
                    // Only report if there are risky operations AND no validation
                    if !has_validation && (has_risky_ops || is_financial_context) {
                        let confidence = self.calculate_confidence(line, &lines, line_num, is_financial_context, has_risky_ops);
                        
                        // Only report high confidence findings to minimize false positives
                        if confidence >= 0.7 {
                            let severity = if is_financial_context && has_risky_ops {
                                Severity::High
                            } else if has_risky_ops {
                                Severity::Medium  
                            } else {
                                Severity::Low
                            };

                            findings.push(
                                Finding::new(
                                    self.name(),
                                    severity,
                                    Category::Security,
                                    confidence,
                                    "Insufficient Input Validation",
                                    &format!(
                                        "Function at line {} accepts parameters {} but performs dangerous operations without sufficient validation: {}. Risk factors: {}. Unvalidated inputs can lead to vulnerabilities.",
                                        line_num,
                                        captures.as_str(),
                                        self.get_risk_operations(&lines, line_num),
                                        self.get_risk_factors(is_financial_context, has_risky_ops)
                                    ),
                                    &file.path,
                                    line_num,
                                    captures.start(),
                                    extract_code_snippet(&file.content, line_num, 3),
                                    "Implement comprehensive input validation: (1) Add require() statements for parameter bounds, (2) Check for zero addresses/IDs, (3) Validate ranges before arithmetic operations, (4) Use checked arithmetic for financial calculations, (5) Add parameter sanitization for arrays/loops.",
                                )
                                .with_context(context.clone())
                                .with_cwe(vec![20, 129, 190]) // Improper Input Validation, Improper Validation of Array Index, Integer Overflow
                                .with_references(vec![
                                    Reference {
                                        title: "OWASP Input Validation Cheat Sheet".to_string(),
                                        url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html".to_string(),
                                        reference_type: ReferenceType::Security,
                                    },
                                ])
                                .with_effort(EstimatedEffort::Easy)
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn has_comprehensive_validation(&self, lines: &[&str], start_line: usize) -> bool {
        // Look for validation in the function (next 20 lines or until next function)
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            // Stop if we reach another function
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            // Check for comprehensive validation patterns
            if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn has_high_risk_operations(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 25, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if HIGH_RISK_OPERATIONS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn is_financial_function(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if FINANCIAL_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn calculate_confidence(&self, line: &str, lines: &[&str], line_num: usize, is_financial: bool, has_risky_ops: bool) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence
        
        // Higher confidence for financial functions
        if is_financial {
            confidence += 0.3;
        }
        
        // Higher confidence for risky operations
        if has_risky_ops {
            confidence += 0.3;
        }
        
        // Check for specific risky parameter types
        if line.contains("amount") || line.contains("value") {
            confidence += 0.2;
        }
        
        if line.contains("Address") || line.contains("Identity") {
            confidence += 0.15;
        }
        
        // Lower confidence if validation patterns are nearby but not recognized
        if self.has_nearby_validation_attempts(lines, line_num) {
            confidence -= 0.2;
        }
        
        confidence.min(1.0)
    }

    fn has_nearby_validation_attempts(&self, lines: &[&str], start_line: usize) -> bool {
        let start = if start_line > 3 { start_line - 3 } else { 0 };
        let end = std::cmp::min(start_line + 10, lines.len());
        
        for i in start..end {
            let line = lines[i];
            if line.contains("if ") && (line.contains("==") || line.contains("!=") || line.contains(">") || line.contains("<")) {
                return true;
            }
        }
        false
    }

    fn get_risk_operations(&self, lines: &[&str], start_line: usize) -> String {
        let mut operations = Vec::new();
        
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if line.contains("transfer") { operations.push("transfer"); }
            if line.contains("mint") { operations.push("mint"); }
            if line.contains("burn") { operations.push("burn"); }
            if line.contains("storage.") && line.contains(".write") { operations.push("storage write"); }
            if line.contains("approve") { operations.push("approve"); }
        }
        
        if operations.is_empty() {
            "dangerous operations".to_string()
        } else {
            operations.join(", ")
        }
    }

    fn get_risk_factors(&self, is_financial: bool, has_risky_ops: bool) -> String {
        let mut factors = Vec::new();
        
        if is_financial {
            factors.push("Financial operation context");
        }
        
        if has_risky_ops {
            factors.push("High-risk operations present");
        }
        
        factors.push("Missing input bounds validation");
        factors.push("Missing overflow protection");
        
        factors.join(", ")
    }
}

impl Detector for InputValidationDetector {
    fn name(&self) -> &'static str {
        "input_validation"
    }
    
    fn description(&self) -> &'static str {
        "Detects insufficient input validation in functions with high-risk operations"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Analyze function parameters for insufficient validation
        all_findings.extend(self.analyze_function_parameters(file, context));
        
        Ok(all_findings)
    }
} 