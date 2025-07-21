use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct UncheckedExternalCallsDetector;

impl UncheckedExternalCallsDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_unchecked_external_calls(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect unchecked external call-specific issues, not reentrancy, access control, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_external_call = false;
        let mut has_return_check = false;
        let mut has_error_handling = false;
        let mut has_success_check = false;
        let mut external_call_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for external calls
            if l.contains("abi(") || l.contains("contract_call(") || l.contains("external_call(") {
                has_external_call = true;
                external_call_lines.push(idx + line_number);
            }
            
            // Check for return value handling
            if l.contains("let result") || l.contains("let response") || l.contains("let call_result") {
                has_return_check = true;
            }
            
            // Check for error handling
            if l.contains("match") && l.contains("Result") {
                has_error_handling = true;
            }
            
            if l.contains("if let") && l.contains("Ok(") {
                has_success_check = true;
            }
            
            // Check for unchecked external calls
            if (l.contains("abi(") || l.contains("contract_call(")) && !has_return_check {
                found = true;
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
        
        if found && has_external_call && (!has_return_check || !has_error_handling || !has_success_check || called_by_public) {
            let mut description = format!("Function '{}' contains unchecked external calls.", function.name);
            if !has_return_check {
                description.push_str(" No return value checking detected.");
            }
            if !has_error_handling {
                description.push_str(" No error handling detected.");
            }
            if !has_success_check {
                description.push_str(" No success validation detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "unchecked_external_calls",
                Severity::High,
                Category::ExternalCalls,
                0.9,
                &format!("Unchecked External Call Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add proper return value checking, error handling, and success validation for external calls.",
            ))
        } else {
            None
        }
    }
}

impl Detector for UncheckedExternalCallsDetector {
    fn name(&self) -> &'static str {
        "unchecked_external_calls"
    }
    fn description(&self) -> &'static str {
        "Detects unchecked external calls using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::ExternalCalls
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_unchecked_external_calls(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 