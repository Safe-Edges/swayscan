use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct LogicErrorsDetector;

impl LogicErrorsDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_logic_errors(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect logic error-specific issues, not business logic, data validation, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_logic_error = false;
        let mut has_overflow_protection = false;
        let mut has_underflow_protection = false;
        let mut has_division_by_zero_check = false;
        let mut logic_error_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for potential overflow/underflow
            if l.contains("+") && l.contains("u") && !l.contains("checked_add") {
                has_logic_error = true;
                logic_error_lines.push(idx + line_number);
            }
            
            if l.contains("-") && l.contains("u") && !l.contains("checked_sub") {
                has_logic_error = true;
                logic_error_lines.push(idx + line_number);
            }
            
            if l.contains("*") && l.contains("u") && !l.contains("checked_mul") {
                has_logic_error = true;
                logic_error_lines.push(idx + line_number);
            }
            
            // Check for division by zero
            if l.contains("/") && !l.contains("checked_div") {
                has_logic_error = true;
                logic_error_lines.push(idx + line_number);
            }
            
            // Check for overflow protection
            if l.contains("checked_add") || l.contains("checked_sub") || l.contains("checked_mul") {
                has_overflow_protection = true;
            }
            
            // Check for underflow protection
            if l.contains("checked_sub") {
                has_underflow_protection = true;
            }
            
            // Check for division by zero protection
            if l.contains("checked_div") || (l.contains("/") && l.contains("!= 0")) {
                has_division_by_zero_check = true;
            }
            
            // Check for logical inconsistencies
            if l.contains("if") && l.contains("else") && l.contains("return") {
                // Check for unreachable code patterns
                if l.contains("return") && l.contains(";") {
                    has_logic_error = true;
                    logic_error_lines.push(idx + line_number);
                }
            }
            
            // Check for dead code patterns
            if l.contains("return") && l.contains(";") && idx < lines.len() - 1 {
                let next_line = lines[idx + 1].trim();
                if !next_line.is_empty() && !next_line.starts_with("}") && !next_line.starts_with("else") {
                    has_logic_error = true;
                    logic_error_lines.push(idx + line_number);
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
        
        if found && has_logic_error && (!has_overflow_protection || !has_underflow_protection || !has_division_by_zero_check || called_by_public) {
            let mut description = format!("Function '{}' contains potential logic errors.", function.name);
            if !has_overflow_protection {
                description.push_str(" No overflow protection detected.");
            }
            if !has_underflow_protection {
                description.push_str(" No underflow protection detected.");
            }
            if !has_division_by_zero_check {
                description.push_str(" No division by zero protection detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "logic_errors",
                Severity::Medium,
                Category::LogicErrors,
                0.8,
                &format!("Logic Error Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Use checked arithmetic operations and add proper overflow/underflow protection.",
            ))
        } else {
            None
        }
    }
}

impl Detector for LogicErrorsDetector {
    fn name(&self) -> &'static str {
        "logic_errors"
    }
    fn description(&self) -> &'static str {
        "Detects logic errors using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::LogicErrors
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_logic_errors(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 