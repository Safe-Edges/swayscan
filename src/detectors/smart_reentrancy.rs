use crate::detectors::{Detector, Finding, Severity, Category, extract_code_snippet};
use crate::detectors::sway_analyzer::{SwayAnalyzer, ExternalCall};
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AnalysisContext};
use uuid::Uuid;

pub struct SmartReentrancyDetector {
    analyzer: SwayAnalyzer,
}

// Sway-specific reentrancy patterns
static SWAY_EXTERNAL_CALLS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)").unwrap(),
        Regex::new(r"force_transfer_to_contract\s*\(").unwrap(),
        Regex::new(r"abi\(.*\)\s*\.call\s*\(").unwrap(),
        Regex::new(r"contract_call\s*\(").unwrap(),
    ]
});

static SWAY_STATE_CHANGES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.(\w+)\.write\s*\(").unwrap(),
        Regex::new(r"storage\.(\w+)\.insert\s*\(").unwrap(),
        Regex::new(r"storage\.(\w+)\.remove\s*\(").unwrap(),
    ]
});

static SWAY_REENTRANCY_GUARDS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*!?\s*storage\.locked\s*\.read\s*\(\s*\)").unwrap(),
        Regex::new(r"storage\.guard\s*\.write\s*\(\s*true\s*\)").unwrap(),
        Regex::new(r"reentrancy_guard").unwrap(),
        Regex::new(r"nonReentrant").unwrap(),
    ]
});

static SAFE_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"#\[storage\(read\)\]").unwrap(),  // Read-only functions
        Regex::new(r"if\s+let\s+Ok\(").unwrap(),       // Checked call results
        Regex::new(r"match\s+.*\.call\s*\(").unwrap(), // Pattern matched calls
    ]
});

impl SmartReentrancyDetector {
    pub fn new() -> Self {
        Self {
            analyzer: SwayAnalyzer::new(),
        }
    }

    fn analyze_function_for_reentrancy(&self, lines: &[&str], func_start: usize, func_end: usize) -> Vec<ReentrancyIssue> {
        let mut issues: Vec<Finding> = Vec::new();
        let mut external_calls = Vec::new();
        let mut state_changes = Vec::new();
        let mut has_guard = false;

        // Scan function body for patterns
        for (idx, line) in lines[func_start..=func_end].iter().enumerate() {
            let actual_line_num = func_start + idx + 1;

            // Check for reentrancy guards
            if SWAY_REENTRANCY_GUARDS.iter().any(|pattern| pattern.is_match(line)) {
                has_guard = true;
            }

            // Find external calls
            for pattern in SWAY_EXTERNAL_CALLS.iter() {
                if let Some(cap) = pattern.captures(line) {
                    external_calls.push(ExternalCallInfo {
                        line_number: actual_line_num,
                        call_type: determine_call_type(line),
                        is_checked: is_call_checked(line, lines, idx + func_start),
                    });
                }
            }

            // Find state changes
            for pattern in SWAY_STATE_CHANGES.iter() {
                if let Some(cap) = pattern.captures(line) {
                    let storage_var = cap.get(1).map_or("unknown", |m| m.as_str());
                    state_changes.push(StateChangeInfo {
                        line_number: actual_line_num,
                        storage_variable: storage_var.to_string(),
                    });
                }
            }
        }

        // Analyze for reentrancy vulnerabilities
        self.detect_reentrancy_violations(&external_calls, &state_changes, has_guard, lines)
    }

    fn detect_reentrancy_violations(
        &self,
        external_calls: &[ExternalCallInfo],
        state_changes: &[StateChangeInfo],
        has_guard: bool,
        lines: &[&str],
    ) -> Vec<ReentrancyIssue> {
        let mut issues = Vec::new();

        // If function has reentrancy guard, it's likely protected
        if has_guard {
            return issues;
        }

        // Check for classic reentrancy pattern: external call followed by state change
        for ext_call in external_calls {
            for state_change in state_changes {
                if state_change.line_number > ext_call.line_number {
                    // This is the dangerous pattern
                    let confidence = self.calculate_confidence(ext_call, state_change, lines);
                    
                    // Only report high confidence issues
                    if confidence > 0.7 {
                        issues.push(ReentrancyIssue {
                            external_call_line: ext_call.line_number,
                            state_change_line: state_change.line_number,
                            call_type: ext_call.call_type.clone(),
                            storage_var: state_change.storage_variable.clone(),
                            confidence,
                            severity: if confidence > 0.9 { Severity::Critical } else { Severity::High },
                        });
                    }
                }
            }
        }

        issues
    }

    fn calculate_confidence(&self, ext_call: &ExternalCallInfo, state_change: &StateChangeInfo, lines: &[&str]) -> f64 {
        let mut confidence: f32 = 0.5; // Base confidence

        // Higher confidence for unchecked transfers
        if ext_call.call_type == "transfer" && !ext_call.is_checked {
            confidence += 0.3;
        }

        // Higher confidence for balance modifications
        if state_change.storage_variable.contains("balance") {
            confidence += 0.2;
        }

        // Lower confidence if there are safety patterns nearby
        let context_start = ext_call.line_number.saturating_sub(3);
        let context_end = (state_change.line_number + 3).min(lines.len());
        
        for line_idx in context_start..context_end {
            if line_idx < lines.len() {
                let line = lines[line_idx];
                
                // Check for safe patterns that reduce confidence
                if SAFE_CALL_PATTERNS.iter().any(|pattern| pattern.is_match(line)) {
                    confidence -= 0.2;
                }
                
                // Check for validation patterns
                if line.contains("require(") || line.contains("assert(") {
                    confidence -= 0.1;
                }
            }
        }

        confidence.clamp(0.0, 1.0).into()
    }
}

impl Detector for SmartReentrancyDetector {
    fn name(&self) -> &'static str {
        "smart_reentrancy_vulnerability"
    }
    fn description(&self) -> &'static str {
        "Detects reentrancy vulnerabilities with high accuracy using advanced Sway-specific analysis"
    }
    fn category(&self) -> Category {
        Category::Reentrancy
    }
    fn default_severity(&self) -> Severity {
        Severity::Critical
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let file_content = &file.content;
        let mut findings = Vec::new();
        let lines: Vec<&str> = file_content.lines().collect();
        let functions = self.parse_sway_functions(&lines);
        for func in functions {
            let issues = self.analyze_function_for_reentrancy(&lines, func.start_line, func.end_line);
            for issue in issues {
                if issue.confidence > 0.7 {
                    let description = format!(
                        "Potential reentrancy vulnerability: external {} call at line {} followed by state change to {} at line {}. Confidence: {:.1}%",
                        issue.call_type,
                        issue.external_call_line,
                        issue.storage_var,
                        issue.state_change_line,
                        issue.confidence * 100.0
                    );
                    let recommendation = "Implement the checks-effects-interactions pattern: (1) Perform validation checks, (2) Update state variables, (3) Make external calls. Consider using a reentrancy guard.".to_string();
                    findings.push(Finding {
                        id: Uuid::new_v4(),
                        detector_name: self.name().to_string(),
                        severity: issue.severity,
                        category: self.category(),
                        confidence: issue.confidence as f64,
                        title: "Reentrancy Vulnerability".to_string(),
                        description,
                        file_path: file.path.clone(),
                        line: issue.external_call_line,
                        column: 1,
                        end_line: None,
                        end_column: None,
                        code_snippet: extract_code_snippet(file_content, issue.external_call_line, 3),
                        recommendation,
                        impact: "An attacker could re-enter the function before state changes are finalized, potentially draining funds or corrupting state.".to_string(),
                        effort: crate::detectors::EstimatedEffort::Hard,
                        references: vec![],
                        cwe_ids: vec![863],
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
struct ExternalCallInfo {
    line_number: usize,
    call_type: String,
    is_checked: bool,
}

#[derive(Debug)]
struct StateChangeInfo {
    line_number: usize,
    storage_variable: String,
}

#[derive(Debug)]
struct ReentrancyIssue {
    external_call_line: usize,
    state_change_line: usize,
    call_type: String,
    storage_var: String,
    confidence: f64,
    severity: Severity,
}

#[derive(Debug)]
struct SwayFunction {
    name: String,
    start_line: usize,
    end_line: usize,
}

impl SmartReentrancyDetector {
    fn parse_sway_functions(&self, lines: &[&str]) -> Vec<SwayFunction> {
        let mut functions = Vec::new();
        let func_pattern = Regex::new(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*\(").unwrap();
        
        let mut current_func: Option<SwayFunction> = None;
        let mut brace_count = 0;
        let mut in_function = false;

        for (idx, line) in lines.iter().enumerate() {
            if let Some(cap) = func_pattern.captures(line) {
                // Start of new function
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
                // Count braces to find function end
                brace_count += line.matches('{').count() as i32;
                brace_count -= line.matches('}').count() as i32;

                if brace_count == 0 && current_func.is_some() {
                    // End of function
                    if let Some(mut func) = current_func.take() {
                        func.end_line = idx;
                        functions.push(func);
                    }
                    in_function = false;
                }
            }
        }

        // Handle last function if file ends
        if let Some(func) = current_func {
            functions.push(func);
        }

        functions
    }
}

fn determine_call_type(line: &str) -> String {
    if line.contains("transfer") {
        "transfer".to_string()
    } else if line.contains("mint_to") {
        "mint".to_string()
    } else if line.contains("call") {
        "contract_call".to_string()
    } else {
        "external_call".to_string()
    }
}

fn is_call_checked(line: &str, lines: &[&str], line_idx: usize) -> bool {
    // Check if return value is handled
    if line.contains("let") && line.contains("=") {
        return true;
    }

    // Check next few lines for error handling
    for i in 1..=3 {
        if line_idx + i < lines.len() {
            let next_line = lines[line_idx + i];
            if next_line.contains("require(") || next_line.contains("assert(") || next_line.contains("match") {
                return true;
            }
        }
    }

    false
} 