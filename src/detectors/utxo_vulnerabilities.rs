use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct UtxoVulnerabilityDetector;

// UTXO-related patterns in Fuel/Sway
static UTXO_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"utxo_id").unwrap(),
        Regex::new(r"input_count\s*\(\s*\)").unwrap(),
        Regex::new(r"input_amount\s*\(").unwrap(),
        Regex::new(r"input_asset_id\s*\(").unwrap(),
        Regex::new(r"input_owner\s*\(").unwrap(),
        Regex::new(r"input_type\s*\(").unwrap(),
        Regex::new(r"output_count\s*\(\s*\)").unwrap(),
        Regex::new(r"output_amount\s*\(").unwrap(),
        Regex::new(r"output_asset_id\s*\(").unwrap(),
    ]
});

// Dangerous UTXO operations
static DANGEROUS_UTXO_OPS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"input_amount\s*\([^)]*\)\s*[+\-*/]").unwrap(), // Arithmetic on input amounts
        Regex::new(r"output_amount\s*\([^)]*\)\s*[+\-*/]").unwrap(), // Arithmetic on output amounts
        Regex::new(r"utxo_id.*==.*utxo_id").unwrap(), // UTXO ID comparison (possible double-spend)
        Regex::new(r"for\s+.*input_count").unwrap(), // Looping over inputs without checks
        Regex::new(r"input_amount.*without.*validation").unwrap(), // Commented patterns
    ]
});

// Balance validation patterns (good)
static BALANCE_VALIDATION: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*input_amount").unwrap(),
        Regex::new(r"assert\s*\(\s*input_amount").unwrap(),
        Regex::new(r"total_input.*>=.*total_output").unwrap(),
        Regex::new(r"balance.*check").unwrap(),
        Regex::new(r"sum.*input.*amount").unwrap(),
        Regex::new(r"verify.*balance").unwrap(),
    ]
});

// Double-spend protection patterns
static DOUBLE_SPEND_PROTECTION: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"utxo.*used").unwrap(),
        Regex::new(r"input.*consumed").unwrap(),
        Regex::new(r"prevent.*double").unwrap(),
        Regex::new(r"nonce").unwrap(),
        Regex::new(r"replay.*protection").unwrap(),
    ]
});

// Asset ID validation patterns
static ASSET_VALIDATION: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*input_asset_id").unwrap(),
        Regex::new(r"assert\s*\(\s*asset_id\s*==").unwrap(),
        Regex::new(r"verify.*asset").unwrap(),
        Regex::new(r"check.*token").unwrap(),
    ]
});

impl UtxoVulnerabilityDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_utxo_operations(&self, content: &str) -> Vec<(usize, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            for pattern in UTXO_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    let op_type = self.classify_utxo_operation(line);
                    findings.push((i + 1, mat.as_str().to_string(), op_type));
                }
            }
        }
        findings
    }

    fn classify_utxo_operation(&self, line: &str) -> String {
        if line.contains("input_amount") {
            "input_amount".to_string()
        } else if line.contains("output_amount") {
            "output_amount".to_string()
        } else if line.contains("input_asset_id") {
            "input_asset_id".to_string()
        } else if line.contains("utxo_id") {
            "utxo_id".to_string()
        } else if line.contains("input_count") {
            "input_count".to_string()
        } else if line.contains("output_count") {
            "output_count".to_string()
        } else {
            "utxo_operation".to_string()
        }
    }

    fn is_dangerous_utxo_operation(&self, line: &str) -> bool {
        for pattern in DANGEROUS_UTXO_OPS.iter() {
            if pattern.is_match(line) {
                return true;
            }
        }
        false
    }

    fn has_balance_validation(&self, function_content: &str) -> bool {
        for pattern in BALANCE_VALIDATION.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_double_spend_protection(&self, function_content: &str) -> bool {
        for pattern in DOUBLE_SPEND_PROTECTION.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_asset_validation(&self, function_content: &str) -> bool {
        for pattern in ASSET_VALIDATION.iter() {
            if pattern.is_match(function_content) {
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
        
        // Get extended function content for analysis
        let end = (start + 80).min(lines.len());
        lines[start..end].join("\n")
    }

    fn analyze_utxo_risks(&self, line: &str, op_type: &str, function_content: &str) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk for UTXO operations without proper validation
        risk_score += 0.4;
        
        // Higher risk for dangerous operations
        if self.is_dangerous_utxo_operation(line) {
            risk_score += 0.4;
        }
        
        // Higher risk based on operation type
        match op_type {
            "input_amount" | "output_amount" => {
                if !self.has_balance_validation(function_content) {
                    risk_score += 0.3;
                }
            },
            "utxo_id" => {
                if !self.has_double_spend_protection(function_content) {
                    risk_score += 0.4;
                }
            },
            "input_asset_id" => {
                if !self.has_asset_validation(function_content) {
                    risk_score += 0.3;
                }
            },
            _ => risk_score += 0.1,
        }
        
        // Higher risk for arithmetic operations on amounts
        if line.contains("+") || line.contains("-") || line.contains("*") || line.contains("/") {
            if line.contains("amount") {
                risk_score += 0.3;
            }
        }
        
        // Higher risk if in loops without bounds checking
        if function_content.contains("for ") && !function_content.contains("require") {
            risk_score += 0.2;
        }
        
        // Higher risk for transfer/mint operations
        if function_content.contains("transfer") || function_content.contains("mint") || function_content.contains("burn") {
            risk_score += 0.2;
        }
        
        // Reduce risk if comprehensive validation exists
        let validation_score = 
            (if self.has_balance_validation(function_content) { 1 } else { 0 }) +
            (if self.has_double_spend_protection(function_content) { 1 } else { 0 }) +
            (if self.has_asset_validation(function_content) { 1 } else { 0 });
        
        match validation_score {
            3 => risk_score *= 0.3, // All validations present
            2 => risk_score *= 0.6, // Most validations present
            1 => risk_score *= 0.8, // Some validation present
            _ => {}, // No additional reduction
        }
        
        risk_score.min(1.0)
    }

    fn get_vulnerability_details(&self, op_type: &str) -> (&str, &str) {
        match op_type {
            "input_amount" | "output_amount" => (
                "UTXO Balance Manipulation",
                "Insufficient balance validation can lead to creating invalid transactions or draining funds"
            ),
            "utxo_id" => (
                "UTXO Double-Spend Risk", 
                "Improper UTXO handling can allow double-spending attacks or transaction replay"
            ),
            "input_asset_id" => (
                "Asset ID Validation Missing",
                "Missing asset ID validation can allow wrong tokens to be processed"
            ),
            _ => (
                "UTXO Handling Vulnerability",
                "Improper UTXO operations can lead to transaction manipulation"
            ),
        }
    }
}

impl Detector for UtxoVulnerabilityDetector {
    fn name(&self) -> &'static str {
        "utxo_vulnerabilities"
    }
    
    fn description(&self) -> &'static str {
        "Detects UTXO-related vulnerabilities specific to Fuel's UTXO model including double-spending and balance manipulation risks"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find UTXO operations
        let utxo_ops = self.find_utxo_operations(&file.content);
        
        for (line_num, operation, op_type) in utxo_ops {
            let line = file.content.lines().nth(line_num - 1).unwrap_or("");
            let function_content = self.extract_function_context(&file.content, line_num);
            
            let confidence = self.analyze_utxo_risks(line, &op_type, &function_content);
            
            if confidence >= 0.7 {
                let severity = if confidence >= 0.9 {
                    Severity::Critical
                } else if confidence >= 0.8 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let (vuln_title, vuln_impact) = self.get_vulnerability_details(&op_type);

                let mut risk_factors = Vec::new();
                if self.is_dangerous_utxo_operation(line) {
                    risk_factors.push("Dangerous UTXO arithmetic operation");
                }
                if !self.has_balance_validation(&function_content) && op_type.contains("amount") {
                    risk_factors.push("Missing balance validation");
                }
                if !self.has_double_spend_protection(&function_content) && op_type == "utxo_id" {
                    risk_factors.push("No double-spend protection");
                }
                if !self.has_asset_validation(&function_content) && op_type.contains("asset") {
                    risk_factors.push("Missing asset ID validation");
                }
                if function_content.contains("for ") && !function_content.contains("require") {
                    risk_factors.push("Unbounded loop over UTXO inputs/outputs");
                }

                let finding = Finding::new(
                    self.name(),
                    severity,
                    self.category(),
                    confidence,
                    vuln_title,
                    &format!(
                        "UTXO operation '{}' at line {} has security risks. {}. Risk factors: {}. In Fuel's UTXO model, improper handling can lead to fund loss or transaction manipulation.",
                        operation.trim(),
                        line_num,
                        vuln_impact,
                        if risk_factors.is_empty() { "General UTXO validation missing".to_string() } else { risk_factors.join(", ") }
                    ),
                    &file.path,
                    line_num,
                    1,
                    extract_code_snippet(&file.content, line_num, 2),
                    &format!(
                        "Implement proper UTXO validation: {} Add comprehensive checks for: (1) Balance conservation (inputs >= outputs), (2) Asset ID validation, (3) Double-spend prevention, (4) Input/output bounds checking.",
                        match op_type.as_str() {
                            "input_amount" | "output_amount" => "Validate all amount calculations with require() statements.",
                            "utxo_id" => "Implement double-spend protection and UTXO uniqueness checks.",
                            "input_asset_id" => "Verify asset IDs match expected values before processing.",
                            _ => "Add proper UTXO validation patterns."
                        }
                    ),
                )
                .with_impact("High - UTXO vulnerabilities can lead to double-spending, fund drainage, or transaction manipulation in Fuel's UTXO model")
                .with_effort(EstimatedEffort::Medium)
                .with_cwe(vec![20, 682, 841]) // CWE-20: Input Validation, CWE-682: Incorrect Calculation, CWE-841: Improper Behavioral Workflow
                .with_references(vec![
                    Reference {
                        title: "Fuel UTXO Model Documentation".to_string(),
                        url: "https://docs.fuel.network/docs/specs/protocol/tx-format/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    },
                    Reference {
                        title: "Sway Transaction Handling".to_string(),
                        url: "https://docs.fuel.network/docs/sway/advanced/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    }
                ])
                .with_context(context.clone());
                
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }
} 