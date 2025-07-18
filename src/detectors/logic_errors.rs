use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct LogicErrorDetector;

// Logic error patterns
static LOGIC_ERROR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"if\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Assignment in if condition
        Regex::new(r"while\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Assignment in while condition
        Regex::new(r"==\s*true\b").unwrap(), // Unnecessary comparison with true
        Regex::new(r"==\s*false\b").unwrap(), // Unnecessary comparison with false
        Regex::new(r"if\s*\(\s*!\s*\w+\s*==\s*false\s*\)").unwrap(), // Double negation
        Regex::new(r"if\s*\(\s*\w+\s*==\s*true\s*\)").unwrap(), // Redundant true comparison
    ]
});

// Off-by-one error patterns
static OFF_BY_ONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"for\s+\w+\s+in\s+0\.\.=?length").unwrap(), // Loop might go beyond bounds
        Regex::new(r"while\s+\w+\s*<=\s*\w*\.len\(\)").unwrap(), // While loop boundary issue
        Regex::new(r"\[\s*\w+\s*\+\s*1\s*\]").unwrap(), // Array access with +1 (potential overflow)
        Regex::new(r"\[\s*\w+\s*\-\s*1\s*\]").unwrap(), // Array access with -1 (potential underflow)
    ]
});

// Incorrect comparison patterns
static INCORRECT_COMPARISONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"if\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Single = instead of ==
        Regex::new(r">=\s*0\s*&&\s*\w+\s*<=\s*\w+").unwrap(), // Redundant >= 0 for unsigned
        Regex::new(r"u\d+.*>=\s*0").unwrap(), // Unsigned integer compared to 0
    ]
});

// State inconsistency patterns
static STATE_INCONSISTENCY: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.[\w\.]*\.write\([^)]*\);\s*storage\.[\w\.]*\.write\([^)]*\);").unwrap(), // Multiple storage writes without checks
        Regex::new(r"balance.*=.*amount.*transfer").unwrap(), // Balance update before transfer
        Regex::new(r"total.*supply.*\+=.*mint").unwrap(), // Supply update order
    ]
});

// Dead code patterns
static DEAD_CODE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"return\s*[^;]*;\s*\w+").unwrap(), // Code after return
        Regex::new(r"revert\s*[^;]*;\s*\w+").unwrap(), // Code after revert
        Regex::new(r"panic\s*[^;]*;\s*\w+").unwrap(), // Code after panic
        Regex::new(r"if\s*\(\s*true\s*\)\s*\{[^}]*\}\s*else\s*\{").unwrap(), // Unreachable else
        Regex::new(r"if\s*\(\s*false\s*\)\s*\{").unwrap(), // Unreachable if block
    ]
});

// Incorrect order patterns
static INCORRECT_ORDER: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer.*require").unwrap(), // Transfer before validation
        Regex::new(r"mint.*require").unwrap(), // Mint before validation
        Regex::new(r"storage\.[\w\.]*\.write.*require").unwrap(), // State change before validation
    ]
});

impl LogicErrorDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_logic_errors(&self, content: &str) -> Vec<(usize, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        // Check for various logic error patterns
        for (i, line) in lines.iter().enumerate() {
            // Assignment in conditions
            for pattern in LOGIC_ERROR_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "logic_error".to_string()));
                }
            }
            
            // Off-by-one errors
            for pattern in OFF_BY_ONE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "off_by_one".to_string()));
                }
            }
            
            // Incorrect comparisons
            for pattern in INCORRECT_COMPARISONS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "incorrect_comparison".to_string()));
                }
            }
            
            // State inconsistency
            for pattern in STATE_INCONSISTENCY.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "state_inconsistency".to_string()));
                }
            }
            
            // Dead code
            for pattern in DEAD_CODE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "dead_code".to_string()));
                }
            }
            
            // Incorrect order
            for pattern in INCORRECT_ORDER.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "incorrect_order".to_string()));
                }
            }
        }
        
        findings
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
        let end = (start + 40).min(lines.len());
        lines[start..end].join("\n")
    }

    fn calculate_logic_risk(&self, line: &str, error_type: &str, function_content: &str) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk varies by error type
        match error_type {
            "logic_error" => risk_score += 0.7, // High risk for logic errors
            "off_by_one" => risk_score += 0.6, // Medium-high risk
            "incorrect_comparison" => risk_score += 0.5, // Medium risk
            "state_inconsistency" => risk_score += 0.8, // High risk
            "dead_code" => risk_score += 0.3, // Lower risk but still issues
            "incorrect_order" => risk_score += 0.9, // Very high risk
            _ => risk_score += 0.4,
        }
        
        // Higher risk in financial functions
        if function_content.contains("transfer") || function_content.contains("mint") || 
           function_content.contains("burn") || function_content.contains("balance") {
            risk_score += 0.2;
        }
        
        // Higher risk for storage operations
        if function_content.contains("storage.") && function_content.contains(".write") {
            risk_score += 0.2;
        }
        
        // Higher risk for external calls
        if function_content.contains("abi(") || function_content.contains("contract_call") {
            risk_score += 0.15;
        }
        
        // Reduce risk if comprehensive validation exists
        let validation_count = [
            function_content.contains("require"),
            function_content.contains("assert"),
            function_content.contains("match"),
            function_content.contains("if let"),
        ].iter().filter(|&&x| x).count();
        
        if validation_count >= 3 {
            risk_score *= 0.7;
        } else if validation_count >= 2 {
            risk_score *= 0.8;
        }
        
        risk_score.min(1.0)
    }

    fn get_error_details(&self, error_type: &str) -> (&str, &str, &str) {
        match error_type {
            "logic_error" => (
                "Logic Error",
                "Logic errors can cause unexpected behavior and potential vulnerabilities",
                "Review conditional logic and fix assignment/comparison errors"
            ),
            "off_by_one" => (
                "Off-by-One Error",
                "Array bounds or loop iteration errors can cause panics or undefined behavior",
                "Check array bounds and loop conditions carefully"
            ),
            "incorrect_comparison" => (
                "Incorrect Comparison",
                "Wrong comparison operators can lead to logic flaws",
                "Use correct comparison operators (== vs = vs >=)"
            ),
            "state_inconsistency" => (
                "State Inconsistency",
                "Inconsistent state updates can break contract invariants",
                "Ensure atomic state updates and proper ordering"
            ),
            "dead_code" => (
                "Dead Code",
                "Unreachable code may indicate logic errors",
                "Remove dead code or fix logic to make it reachable"
            ),
            "incorrect_order" => (
                "Incorrect Operation Order",
                "Wrong order of operations can cause security vulnerabilities",
                "Follow checks-effects-interactions pattern"
            ),
            _ => (
                "Logic Error",
                "Logic error detected",
                "Review and fix the logic error"
            ),
        }
    }
}

impl Detector for LogicErrorDetector {
    fn name(&self) -> &'static str {
        "logic_errors"
    }
    
    fn description(&self) -> &'static str {
        "Detects logic errors including off-by-one errors, incorrect comparisons, and state inconsistencies"
    }
    
    fn category(&self) -> Category {
        Category::Reliability
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find logic errors
        let logic_errors = self.find_logic_errors(&file.content);
        
        for (line_num, pattern, error_type) in logic_errors {
            let line = file.content.lines().nth(line_num - 1).unwrap_or("");
            let function_content = self.extract_function_context(&file.content, line_num);
            
            let confidence = self.calculate_logic_risk(line, &error_type, &function_content);
            
            if confidence >= 0.6 {
                let severity = if confidence >= 0.9 {
                    Severity::High
                } else if confidence >= 0.7 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let (title, impact, recommendation) = self.get_error_details(&error_type);

                let mut risk_factors = Vec::new();
                if function_content.contains("transfer") || function_content.contains("mint") {
                    risk_factors.push("Financial operation context");
                }
                if function_content.contains("storage.") && function_content.contains(".write") {
                    risk_factors.push("State modification");
                }
                if function_content.contains("abi(") || function_content.contains("contract_call") {
                    risk_factors.push("External call context");
                }

                let finding = Finding::new(
                    self.name(),
                    severity,
                    self.category(),
                    confidence,
                    title,
                    &format!(
                        "{} detected at line {}: '{}'. {}. Risk factors: {}.",
                        title,
                        line_num,
                        pattern.trim(),
                        impact,
                        if risk_factors.is_empty() { "None identified".to_string() } else { risk_factors.join(", ") }
                    ),
                    &file.path,
                    line_num,
                    1,
                    extract_code_snippet(&file.content, line_num, 2),
                    recommendation,
                )
                .with_impact(&format!("Medium - {} can cause unexpected behavior or vulnerabilities", title.to_lowercase()))
                .with_effort(EstimatedEffort::Easy)
                .with_cwe(vec![754, 682, 561]) // CWE-754: Improper Check for Unusual Conditions, CWE-682: Incorrect Calculation, CWE-561: Dead Code
                .with_references(vec![
                    Reference {
                        title: "Sway Best Practices".to_string(),
                        url: "https://docs.fuel.network/docs/sway/advanced/best-practices/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    },
                    Reference {
                        title: "Common Programming Errors".to_string(),
                        url: "https://cwe.mitre.org/data/definitions/754.html".to_string(),
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