use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct MissingLogsDetector;

impl MissingLogsDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_missing_logs(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect missing logs-specific issues, not business logic, access control, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_critical_operation = false;
        let mut has_logging = false;
        let mut has_events = false;
        let mut operation_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for critical operations that should be logged
            if l.contains("transfer") || l.contains("mint") || l.contains("burn") || l.contains("withdraw") || 
               l.contains("deposit") || l.contains("stake") || l.contains("unstake") || l.contains("claim") {
                has_critical_operation = true;
                operation_lines.push(idx + line_number);
            }
            
            // Check for logging mechanisms
            if l.contains("log") || l.contains("emit") || l.contains("event") {
                has_logging = true;
            }
            
            // Check for event declarations
            if l.contains("event") || l.contains("struct") {
                has_events = true;
            }
            
            // Check for state changes without logging
            if l.contains("storage") && (l.contains("write") || l.contains("set")) {
                if !l.contains("log") && !l.contains("emit") {
                    found = true;
                }
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
        
        if found && has_critical_operation && (!has_logging || !has_events || called_by_public) {
            let mut description = format!("Function '{}' contains critical operations without proper logging.", function.name);
            if !has_logging {
                description.push_str(" No logging mechanisms detected.");
            }
            if !has_events {
                description.push_str(" No event declarations detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "missing_logs",
                Severity::Medium,
                Category::Security,
                0.7,
                &format!("Missing Logs Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add proper logging and event emissions for critical operations.",
            ))
        } else {
            None
        }
    }
}

impl Detector for MissingLogsDetector {
    fn name(&self) -> &'static str {
        "missing_logs"
    }
    fn description(&self) -> &'static str {
        "Detects critical operations without proper logging mechanisms using advanced AST-based analysis."
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
                if let Some(finding) = self.analyze_function_missing_logs(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}