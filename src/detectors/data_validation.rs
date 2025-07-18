use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct DataValidationDetector;

// Function parameters that need validation
static PARAMETER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*u\d+)").unwrap(), // Unsigned integer parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*Address)").unwrap(), // Address parameters  
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*AssetId)").unwrap(), // Asset ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*ContractId)").unwrap(), // Contract ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*b256)").unwrap(), // Hash parameters
    ]
});

// Validation patterns (good practices)
static VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*\w+\s*[><!]=?\s*\d+").unwrap(), // Boundary checks
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Address::zero\(\)").unwrap(), // Zero address checks
        Regex::new(r"require\s*\(\s*\w+\s*>\s*0").unwrap(), // Non-zero checks
        Regex::new(r"assert\s*\(\s*\w+").unwrap(), // Assert statements
        Regex::new(r"revert\s*\(").unwrap(), // Explicit reverts
        Regex::new(r"(?i)validate|check|verify").unwrap(), // Validation functions
    ]
});

// Dangerous operations requiring validation
static DANGEROUS_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\(\s*\w+").unwrap(), // Asset transfers
        Regex::new(r"mint_to\s*\(\s*\w+").unwrap(), // Minting
        Regex::new(r"burn\s*\(\s*\w+").unwrap(), // Burning
        Regex::new(r"storage\.\w+\.write\s*\(\s*\w+").unwrap(), // Storage writes
        Regex::new(r"force_transfer_to_contract\s*\(\s*\w+").unwrap(), // Force transfers
        Regex::new(r"\w+\s*\[\s*\w+\s*\]").unwrap(), // Array access
    ]
});

// Array and bounds checking patterns
static ARRAY_ACCESS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\w+\s*\[\s*\w+\s*\]").unwrap(), // Direct array access
        Regex::new(r"get\s*\(\s*\w+\s*\)").unwrap(), // Vector/map get operations
        Regex::new(r"remove\s*\(\s*\w+\s*\)").unwrap(), // Remove operations
        Regex::new(r"insert\s*\(\s*\w+\s*,").unwrap(), // Insert operations
    ]
});

// External input sources
static EXTERNAL_INPUT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"msg\.data|call_data").unwrap(), // Message data
        Regex::new(r"msg\.value|msg\.asset_id").unwrap(), // Message value/asset
        Regex::new(r"input\s*:|param\s*:").unwrap(), // Function inputs
        Regex::new(r"abi\([^)]+\)\.").unwrap(), // ABI calls (external)
    ]
});

impl DataValidationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_missing_input_validation(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;

            // Check for function parameters without validation
            for pattern in PARAMETER_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let has_validation = self.has_parameter_validation(&lines, line_num);
                    let has_dangerous_ops = self.has_dangerous_operations(&lines, line_num);
                    
                    if !has_validation && has_dangerous_ops {
                        let confidence = if line.contains("Address") || line.contains("AssetId") {
                            0.9 // High confidence for address/asset validation
                        } else if line.contains("u64") || line.contains("u256") {
                            0.8 // High confidence for amount validation
                        } else {
                            0.7
                        };

                        findings.push(
                            Finding::new(
                                self.name(),
                                Severity::High,
                                Category::Security,
                                confidence,
                                "Missing Input Validation",
                                &format!(
                                    "Function parameter '{}' is used in security-critical operations without proper validation. This could lead to unexpected behavior or vulnerabilities.",
                                    captures.as_str()
                                ),
                                &file.path,
                                line_num,
                                captures.start(),
                                extract_code_snippet(&file.content, line_num, 3),
                                "Add input validation using require() statements to check parameter bounds, non-zero values, valid addresses, and other constraints before using parameters in critical operations.",
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

            // Check for array access without bounds checking
            for pattern in ARRAY_ACCESS_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let has_bounds_check = self.has_bounds_checking(&lines, line_num);
                    
                    if !has_bounds_check {
                        findings.push(
                            Finding::new(
                                self.name(),
                                Severity::Medium,
                                Category::Security,
                                0.8,
                                "Missing Bounds Checking",
                                &format!(
                                    "Array or collection access '{}' without bounds checking. This could lead to out-of-bounds access or panic conditions.",
                                    captures.as_str()
                                ),
                                &file.path,
                                line_num,
                                captures.start(),
                                extract_code_snippet(&file.content, line_num, 2),
                                "Add bounds checking before array access using length checks or use safe access methods that return Option types.",
                            )
                            .with_context(context.clone())
                            .with_cwe(vec![129, 125]) // Improper Validation of Array Index, Out-of-bounds Read
                            .with_effort(EstimatedEffort::Easy)
                        );
                    }
                }
            }
        }

        findings
    }

    fn analyze_zero_value_checks(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for transfers without zero checks
            if line.contains("transfer") && !line.contains("require") {
                if let Some(captures) = Regex::new(r"transfer\s*\([^)]*amount\s*[:,]\s*(\w+)").unwrap().find(line) {
                    let lines: Vec<&str> = file.content.lines().collect();
                    let has_zero_check = self.has_zero_amount_check(&lines, line_num);
                    
                    if !has_zero_check {
                        findings.push(
                            Finding::new(
                                self.name(),
                                Severity::Medium,
                                Category::Security,
                                0.85,
                                "Missing Zero Amount Check",
                                "Transfer operation without checking for zero amount. This wastes gas and may indicate logical errors.",
                                &file.path,
                                line_num,
                                captures.start(),
                                extract_code_snippet(&file.content, line_num, 2),
                                "Add require(amount > 0) before transfer operations to prevent zero-value transfers.",
                            )
                            .with_context(context.clone())
                            .with_cwe(vec![20])
                            .with_effort(EstimatedEffort::Trivial)
                        );
                    }
                }
            }

            // Check for zero address usage
            if line.contains("Address") && !line.contains("zero") && !line.contains("require") {
                if DANGEROUS_OPERATIONS.iter().any(|p| p.is_match(line)) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Medium,
                            Category::Security,
                            0.75,
                            "Missing Zero Address Check",
                            "Operation using address parameter without checking for zero address. This could lead to permanent loss of assets.",
                            &file.path,
                            line_num,
                            0,
                            extract_code_snippet(&file.content, line_num, 2),
                            "Add require(address != Address::zero()) to prevent operations with zero addresses.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![20])
                        .with_effort(EstimatedEffort::Trivial)
                    );
                }
            }
        }

        findings
    }

    fn has_parameter_validation(&self, lines: &[&str], start_line: usize) -> bool {
        // Look for validation in the function (next 15 lines or until next function)
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn has_dangerous_operations(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if DANGEROUS_OPERATIONS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn has_bounds_checking(&self, lines: &[&str], start_line: usize) -> bool {
        // Check a few lines before and after for bounds checking
        let start = if start_line > 3 { start_line - 3 } else { 0 };
        let end = std::cmp::min(start_line + 3, lines.len());
        
        for i in start..end {
            let line = lines[i];
            if line.contains("len()") || line.contains("length") || 
               line.contains("require") || line.contains("assert") {
                return true;
            }
        }
        false
    }

    fn has_zero_amount_check(&self, lines: &[&str], start_line: usize) -> bool {
        // Check a few lines before for zero amount validation
        let start = if start_line > 5 { start_line - 5 } else { 0 };
        
        for i in start..start_line {
            let line = lines[i];
            if line.contains("require") && (line.contains("> 0") || line.contains("!= 0")) {
                return true;
            }
        }
        false
    }
}

impl Detector for DataValidationDetector {
    fn name(&self) -> &'static str {
        "data_validation"
    }
    
    fn description(&self) -> &'static str {
        "Checks for proper input validation, bounds checking, and data sanitization"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Analyze for missing input validation
        all_findings.extend(self.analyze_missing_input_validation(file, context));
        
        // Analyze for missing zero value checks
        all_findings.extend(self.analyze_zero_value_checks(file, context));
        
        Ok(all_findings)
    }
} 