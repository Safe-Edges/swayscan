use crate::detectors::{Detector, Finding, Severity, Category, extract_code_snippet};
use crate::detectors::sway_analyzer::SwayAnalyzer;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AnalysisContext};
use uuid::Uuid;

pub struct SmartAccessControlDetector {
    analyzer: SwayAnalyzer,
}

// Sway-specific access control patterns
static SWAY_ACCESS_CHECKS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*msg_sender\(\)\s*==\s*storage\.owner").unwrap(),
        Regex::new(r"require\s*\(\s*msg_sender\(\)\s*==\s*storage\.admin").unwrap(),
        Regex::new(r"assert\s*\(\s*msg_sender\(\)\s*==").unwrap(),
        Regex::new(r"only_owner\s*\(").unwrap(),
        Regex::new(r"only_admin\s*\(").unwrap(),
        Regex::new(r"check_access\s*\(").unwrap(),
    ]
});

static SWAY_PROTECTED_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.(\w+)\.write\s*\(").unwrap(),  // Storage writes
        Regex::new(r"mint_to\s*\(").unwrap(),                // Minting
        Regex::new(r"burn\s*\(").unwrap(),                   // Burning
        Regex::new(r"transfer\s*\(.*,.*,.*\)").unwrap(),     // Transfers
        Regex::new(r"storage\.owner\s*\.write").unwrap(),    // Owner changes
        Regex::new(r"storage\.admin\s*\.write").unwrap(),    // Admin changes
    ]
});

// Safe patterns that don't need access control
static SAFE_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.(\w+)\.read\s*\(\s*\)").unwrap(),    // Read operations
        Regex::new(r"#\[storage\(read\)\]").unwrap(),             // Read-only functions
        Regex::new(r"view_").unwrap(),                            // View functions
        Regex::new(r"get_").unwrap(),                             // Getter functions
        Regex::new(r"balance_of\s*\(").unwrap(),                  // Balance queries
        Regex::new(r"total_supply\s*\(\s*\)").unwrap(),          // Supply queries
    ]
});

static INHERENT_PROTECTIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"payable").unwrap(),                          // Payable functions have built-in protection
        Regex::new(r"#\[payable\]").unwrap(),                    // Payable attribute
        Regex::new(r"msg_amount\(\)").unwrap(),                  // Amount-based functions
    ]
});

impl SmartAccessControlDetector {
    pub fn new() -> Self {
        Self {
            analyzer: SwayAnalyzer::new(),
        }
    }

    fn analyze_function(&self, lines: &[&str], func_start: usize, func_end: usize, func_name: &str) -> Vec<AccessControlIssue> {
        let mut issues = Vec::new();
        
        // Skip view/getter functions - they typically don't need access control
        if self.is_view_function(func_name) {
            return issues;
        }

        let mut has_access_check = false;
        let mut protected_operations = Vec::new();
        let mut has_inherent_protection = false;

        // Scan function for patterns
        for (idx, line) in lines[func_start..=func_end].iter().enumerate() {
            let actual_line_num = func_start + idx + 1;

            // Check for access control
            if SWAY_ACCESS_CHECKS.iter().any(|pattern| pattern.is_match(line)) {
                has_access_check = true;
            }

            // Check for inherent protections
            if INHERENT_PROTECTIONS.iter().any(|pattern| pattern.is_match(line)) {
                has_inherent_protection = true;
            }

            // Find protected operations
            for pattern in SWAY_PROTECTED_OPERATIONS.iter() {
                if let Some(cap) = pattern.captures(line) {
                    // Skip if it's a safe operation
                    if !SAFE_OPERATIONS.iter().any(|safe| safe.is_match(line)) {
                        protected_operations.push(ProtectedOperation {
                            line_number: actual_line_num,
                            operation: self.extract_operation_type(line),
                            is_critical: self.is_critical_operation(line),
                        });
                    }
                }
            }
        }

        // Analyze if access control is needed
        if !protected_operations.is_empty() && !has_access_check && !has_inherent_protection {
            let confidence = self.calculate_confidence(&protected_operations, func_name, lines, func_start, func_end);
            
            // Only report high confidence issues
            if confidence > 0.7 {
                issues.push(AccessControlIssue {
                    function_name: func_name.to_string(),
                    line_number: func_start + 1,
                    operations: protected_operations,
                    confidence,
                    severity: if confidence > 0.9 { Severity::High } else { Severity::Medium },
                });
            }
        }

        issues
    }

    fn is_view_function(&self, func_name: &str) -> bool {
        func_name.starts_with("get_") || 
        func_name.starts_with("view_") || 
        func_name.starts_with("read_") ||
        func_name.starts_with("balance_") ||
        func_name.starts_with("total_") ||
        func_name.contains("query")
    }

    fn extract_operation_type(&self, line: &str) -> String {
        if line.contains("mint_to") { "mint".to_string() }
        else if line.contains("burn") { "burn".to_string() }
        else if line.contains("transfer") { "transfer".to_string() }
        else if line.contains("storage") && line.contains("write") { "storage_write".to_string() }
        else if line.contains("owner") { "ownership_change".to_string() }
        else { "privileged_operation".to_string() }
    }

    fn is_critical_operation(&self, line: &str) -> bool {
        line.contains("owner") || 
        line.contains("admin") || 
        line.contains("mint") || 
        line.contains("burn") ||
        line.contains("emergency")
    }

    fn calculate_confidence(&self, operations: &[ProtectedOperation], func_name: &str, lines: &[&str], func_start: usize, func_end: usize) -> f64 {
        let mut confidence: f32 = 0.6; // Base confidence

        // Higher confidence for critical operations
        if operations.iter().any(|op| op.is_critical) {
            confidence += 0.3;
        }

        // Higher confidence for functions with privileged names
        if func_name.contains("admin") || func_name.contains("owner") || func_name.contains("set_") {
            confidence += 0.2;
        }

        // Lower confidence for constructor-like functions
        if func_name.contains("init") || func_name.contains("constructor") {
            confidence -= 0.3;
        }

        // Check for any safety patterns in the function
        let function_body = lines[func_start..=func_end].join("\n");
        
        // Lower confidence if there are checks we might have missed
        if function_body.contains("revert") || function_body.contains("panic") {
            confidence -= 0.1;
        }

        // Lower confidence for very simple functions
        if operations.len() == 1 && lines[func_start..=func_end].len() < 5 {
            confidence -= 0.2;
        }

        confidence.clamp(0.0, 1.0).into()
    }

    fn parse_sway_functions(&self, lines: &[&str]) -> Vec<SwayFunction> {
        let mut functions = Vec::new();
        let func_pattern = Regex::new(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*\(").unwrap();
        
        let mut current_func: Option<SwayFunction> = None;
        let mut brace_count = 0;
        let mut in_function = false;

        for (idx, line) in lines.iter().enumerate() {
            if let Some(cap) = func_pattern.captures(line) {
                if let Some(func) = current_func.take() {
                    functions.push(func);
                }
                
                current_func = Some(SwayFunction {
                    name: cap.get(1).unwrap().as_str().to_string(),
                    start_line: idx,
                    end_line: idx,
                });
                brace_count = 0;
                in_function = true;
            }

            if in_function {
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if brace_count == 0 && current_func.is_some() {
                    if let Some(mut func) = current_func.take() {
                        func.end_line = idx;
                        functions.push(func);
                    }
                    in_function = false;
                }
            }
        }

        if let Some(func) = current_func {
            functions.push(func);
        }

        functions
    }
}

impl Detector for SmartAccessControlDetector {
    fn name(&self) -> &'static str {
        "smart_access_control"
    }
    fn description(&self) -> &'static str {
        "Detects missing access control with high accuracy using Sway-specific analysis"
    }
    fn category(&self) -> Category {
        Category::AccessControl
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let file_content = &file.content;
        let mut findings = Vec::new();
        let lines: Vec<&str> = file_content.lines().collect();
        let functions = self.parse_sway_functions(&lines);
        for func in functions {
            let issues = self.analyze_function(&lines, func.start_line, func.end_line, &func.name);
            for issue in issues {
                if issue.confidence > 0.7 {
                    let operations_desc = issue.operations.iter()
                        .map(|op| format!("{} (line {})", op.operation, op.line_number))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let description = format!(
                        "Function '{}' performs privileged operations ({}) without proper access control. Confidence: {:.1}%",
                        issue.function_name,
                        operations_desc,
                        issue.confidence * 100.0
                    );
                    let recommendation = "Add access control checks using require() with msg_sender() verification, or implement a role-based access control system.".to_string();
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        detector_name: self.name().to_string(),
                        severity: issue.severity,
                        category: self.category(),
                        confidence: issue.confidence as f64,
                        title: "Missing Access Control".to_string(),
                        description,
                        file_path: file.path.clone(),
                        line: issue.line_number,
                        column: 1,
                        end_line: None,
                        end_column: None,
                        code_snippet: extract_code_snippet(file_content, issue.line_number, 3),
                        recommendation,
                        impact: "Unauthorized users may be able to execute privileged operations, potentially leading to loss of funds or contract compromise.".to_string(),
                        effort: crate::detectors::EstimatedEffort::Medium,
                        references: vec![],
                        cwe_ids: vec![284],
                        owasp_category: None,
                        tags: vec![],
                        created_at: chrono::Utc::now(),
                        fingerprint: String::new(),
                        context: AnalysisContext::default(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

#[derive(Debug)]
struct AccessControlIssue {
    function_name: String,
    line_number: usize,
    operations: Vec<ProtectedOperation>,
    confidence: f64,
    severity: Severity,
}

#[derive(Debug)]
struct ProtectedOperation {
    line_number: usize,
    operation: String,
    is_critical: bool,
}

#[derive(Debug)]
struct SwayFunction {
    name: String,
    start_line: usize,
    end_line: usize,
} 