use crate::detectors::{Detector, Finding, Severity, Category, extract_code_snippet};
use crate::detectors::sway_analyzer::SwayAnalyzer;
use regex::Regex;
use once_cell::sync::Lazy;
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AnalysisContext};
use uuid::Uuid;

pub struct SmartExternalCallDetector {
    analyzer: SwayAnalyzer,
}

// Sway-specific external call patterns that need checking
static SWAY_EXTERNAL_CALLS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)").unwrap(),
        Regex::new(r"force_transfer_to_contract\s*\(").unwrap(),
        Regex::new(r"abi\s*\([^)]+\)\s*\.(\w+)\s*\(").unwrap(),
        Regex::new(r"contract_call\s*\(").unwrap(),
    ]
});

// Patterns that indicate the call result is being checked
static CHECKED_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"let\s+\w+\s*=\s*transfer").unwrap(),
        Regex::new(r"if\s+let\s+Ok\(").unwrap(),
        Regex::new(r"match\s+.*\{").unwrap(),
        Regex::new(r"\.unwrap_or\(").unwrap(),
        Regex::new(r"\.expect\(").unwrap(),
    ]
});

// Safe patterns that don't need checking
static SAFE_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"^\s*fn\s+\w+").unwrap(),                    // Function declarations
        Regex::new(r"^\s*//").unwrap(),                          // Comments
        Regex::new(r"#\[storage\(read\)\]").unwrap(),            // Read-only functions
        Regex::new(r"view_").unwrap(),                           // View functions
        Regex::new(r"balance_of\s*\(").unwrap(),                 // Balance queries
    ]
});

// Critical financial operations that must be checked
static CRITICAL_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer.*amount").unwrap(),
        Regex::new(r"mint_to.*amount").unwrap(),
        Regex::new(r"force_transfer").unwrap(),
    ]
});

impl SmartExternalCallDetector {
    pub fn new() -> Self {
        Self {
            analyzer: SwayAnalyzer::new(),
        }
    }

    fn analyze_external_call(&self, line: &str, line_number: usize, lines: &[&str], context_start: usize) -> Option<ExternalCallIssue> {
        // Skip safe patterns
        if SAFE_CALL_PATTERNS.iter().any(|pattern| pattern.is_match(line)) {
            return None;
        }

        // Find external call
        let call_info = self.extract_call_info(line)?;
        
        // Check if this call is being handled properly
        let is_checked = self.is_call_result_checked(line, lines, line_number, context_start);
        
        if !is_checked {
            let confidence = self.calculate_confidence(&call_info, line, lines, line_number);
            
            // Only report high confidence issues
            if confidence > 0.7 {
                return Some(ExternalCallIssue {
                    line_number,
                    call_type: call_info.call_type,
                    target: call_info.target,
                    is_critical: call_info.is_critical,
                    confidence,
                    severity: if call_info.is_critical && confidence > 0.9 { 
                        Severity::High 
                    } else { 
                        Severity::Medium 
                    },
                });
            }
        }

        None
    }

    fn extract_call_info(&self, line: &str) -> Option<ExternalCallInfo> {
        for pattern in SWAY_EXTERNAL_CALLS.iter() {
            if let Some(cap) = pattern.captures(line) {
                let call_type = if line.contains("transfer") {
                    "transfer".to_string()
                } else if line.contains("force_transfer") {
                    "force_transfer".to_string()
                } else if line.contains("abi") {
                    cap.get(1).map_or("abi_call".to_string(), |m| m.as_str().to_string())
                } else {
                    "contract_call".to_string()
                };

                let is_critical = CRITICAL_OPERATIONS.iter().any(|pattern| pattern.is_match(line));

                return Some(ExternalCallInfo {
                    call_type,
                    target: cap.get(1).map(|m| m.as_str().to_string()),
                    is_critical,
                });
            }
        }
        None
    }

    fn is_call_result_checked(&self, line: &str, lines: &[&str], line_number: usize, context_start: usize) -> bool {
        // Check the line itself for immediate result handling
        if CHECKED_CALL_PATTERNS.iter().any(|pattern| pattern.is_match(line)) {
            return true;
        }

        // Check the next few lines for result handling
        let check_range = (line_number + 1)..(line_number + 4).min(lines.len());
        for next_line_idx in check_range {
            if next_line_idx < lines.len() {
                let next_line = lines[next_line_idx];
                
                // Look for error handling patterns
                if next_line.contains("require(") || 
                   next_line.contains("assert(") ||
                   next_line.contains("revert(") ||
                   next_line.contains("if") && next_line.contains("Ok") ||
                   next_line.contains("match") {
                    return true;
                }
            }
        }

        // Check if we're in a larger control structure that handles errors
        let context_end = (line_number + 10).min(lines.len());
        for idx in (line_number + 1)..context_end {
            if idx < lines.len() {
                let context_line = lines[idx];
                if context_line.contains("Result<") || 
                   context_line.contains("unwrap_or") ||
                   context_line.contains("expect(") {
                    return true;
                }
            }
        }

        false
    }

    fn calculate_confidence(&self, call_info: &ExternalCallInfo, line: &str, lines: &[&str], line_number: usize) -> f64 {
        let mut confidence: f32 = 0.6; // Base confidence

        // Higher confidence for critical operations
        if call_info.is_critical {
            confidence += 0.3;
        }

        // Higher confidence for transfer operations with amounts
        if call_info.call_type == "transfer" && line.contains("amount") {
            confidence += 0.2;
        }

        // Lower confidence if it's in a test or example
        let context = lines.get(line_number.saturating_sub(5)..line_number + 5)
            .unwrap_or(&[])
            .join("\n");
            
        if context.contains("test") || context.contains("example") || context.contains("demo") {
            confidence -= 0.3;
        }

        // Lower confidence for very simple lines (might be declarations)
        if line.trim().len() < 30 {
            confidence -= 0.1;
        }

        // Lower confidence if there are safety comments nearby
        if context.contains("// safe") || context.contains("// checked") {
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

impl Detector for SmartExternalCallDetector {
    fn name(&self) -> &'static str {
        "smart_unchecked_external_calls"
    }
    fn description(&self) -> &'static str {
        "Detects unchecked external calls with high accuracy using Sway-specific analysis"
    }
    fn category(&self) -> Category {
        Category::ExternalCalls
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
            for line_idx in func.start_line..=func.end_line {
                if line_idx < lines.len() {
                    let line = lines[line_idx];
                    if let Some(issue) = self.analyze_external_call(line, line_idx + 1, &lines, func.start_line) {
                        let description = format!(
                            "Unchecked external {} call. The return value is not validated, which could lead to silent failures. Confidence: {:.1}%",
                            issue.call_type,
                            issue.confidence * 100.0
                        );
                        let recommendation = "Handle the return value of external calls properly: (1) Assign to a variable and check, (2) Use pattern matching for Result types, (3) Add require() or assert() for critical calls.".to_string();
                        findings.push(Finding {
                            id: Uuid::new_v4(),
                            detector_name: self.name().to_string(),
                            severity: issue.severity,
                            category: self.category(),
                            confidence: issue.confidence as f64,
                            title: "Unchecked External Call".to_string(),
                            description,
                            file_path: file.path.clone(),
                            line: issue.line_number,
                            column: 1,
                            end_line: None,
                            end_column: None,
                            code_snippet: extract_code_snippet(file_content, issue.line_number, 3),
                            recommendation,
                            impact: "Failed external calls may not be detected, potentially leading to unexpected behavior or loss of funds.".to_string(),
                            effort: crate::detectors::EstimatedEffort::Medium,
                            references: vec![],
                            cwe_ids: vec![252],
                            owasp_category: None,
                            tags: vec![],
                            created_at: chrono::Utc::now(),
                            fingerprint: String::new(),
                            context: AnalysisContext::default(),
                        });
                    }
                }
            }
        }
        Ok(findings)
    }
}

#[derive(Debug)]
struct ExternalCallInfo {
    call_type: String,
    target: Option<String>,
    is_critical: bool,
}

#[derive(Debug)]
struct ExternalCallIssue {
    line_number: usize,
    call_type: String,
    target: Option<String>,
    is_critical: bool,
    confidence: f64,
    severity: Severity,
}

#[derive(Debug)]
struct SwayFunction {
    name: String,
    start_line: usize,
    end_line: usize,
} 