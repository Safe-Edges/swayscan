use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct SwayAnalyzerDetector;

impl SwayAnalyzerDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_sway_analyzer(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect sway analyzer-specific issues, not other specific detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_sway_specific_patterns = false;
        let mut has_unsafe_patterns = false;
        let mut has_validation = false;
        let mut has_access_control = false;
        let mut pattern_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for Sway-specific patterns
            if l.contains("storage.") || l.contains("msg_sender()") || l.contains("transfer") {
                has_sway_specific_patterns = true;
                pattern_lines.push(idx + line_number);
            }
            
            // Check for unsafe patterns
            if l.contains("unwrap()") || l.contains("expect(") || l.contains("panic!") {
                has_unsafe_patterns = true;
            }
            
            // Check for validation
            if l.contains("require") || l.contains("assert") || l.contains("validate") {
                has_validation = true;
            }
            
            // Check for access control
            if l.contains("owner") || l.contains("admin") || l.contains("authorized") {
                has_access_control = true;
            }
            
            // Check for potential issues
            if has_sway_specific_patterns && has_unsafe_patterns && (!has_validation || !has_access_control) {
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
        
        if found && has_sway_specific_patterns && (has_unsafe_patterns || called_by_public) {
            let mut description = format!("Function '{}' contains Sway-specific patterns with potential issues.", function.name);
            if has_unsafe_patterns {
                description.push_str(" Unsafe patterns detected.");
            }
            if !has_validation {
                description.push_str(" No validation detected.");
            }
            if !has_access_control {
                description.push_str(" No access control detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "sway_analyzer",
                Severity::Medium,
                Category::Security,
                0.6,
                &format!("Sway Analyzer Issue Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add proper validation, access control, and safe error handling for Sway-specific operations.",
            ))
        } else {
            None
        }
    }
}

impl Detector for SwayAnalyzerDetector {
    fn name(&self) -> &'static str {
        "sway_analyzer"
    }
    fn description(&self) -> &'static str {
        "Analyzes Sway-specific patterns for potential security issues using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Security
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_sway_analyzer(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 