use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct DataValidationDetector;

impl DataValidationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_data_validation(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect data validation-specific issues, not input validation, business logic, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_validation = false;
        let mut has_bounds_check = false;
        let mut has_zero_check = false;
        let mut has_address_validation = false;
        let mut data_validation_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for data validation patterns
            if l.contains("require(") && (l.contains(">") || l.contains("<") || l.contains("!=") || l.contains("==")) {
                has_validation = true;
            }
            
            if l.contains("assert(") {
                has_validation = true;
            }
            
            // Check for bounds checking
            if l.contains("[") && l.contains("]") {
                data_validation_lines.push(idx + line_number);
                if l.contains("length") || l.contains("size") || l.contains("bounds") {
                    has_bounds_check = true;
                }
            }
            
            // Check for zero value checks
            if l.contains("transfer(") || l.contains("mint_to(") || l.contains("burn(") {
                if l.contains("> 0") || l.contains("!= 0") {
                    has_zero_check = true;
                }
            }
            
            // Check for address validation
            if l.contains("Address") && (l.contains("zero()") || l.contains("!= Address::zero()")) {
                has_address_validation = true;
            }
            
            // Check for array access without bounds checking
            if l.contains("[") && l.contains("]") && !has_bounds_check {
                found = true;
            }
            
            // Check for dangerous operations without validation
            if (l.contains("transfer(") || l.contains("mint_to(") || l.contains("burn(") || l.contains("storage.")) && !has_validation {
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
        
        if found && (!has_validation || !has_bounds_check || !has_zero_check || !has_address_validation || called_by_public) {
            let mut description = format!("Function '{}' contains data validation issues.", function.name);
            if !has_validation {
                description.push_str(" No input validation detected.");
            }
            if !has_bounds_check {
                description.push_str(" No bounds checking detected.");
            }
            if !has_zero_check {
                description.push_str(" No zero value checks detected.");
            }
            if !has_address_validation {
                description.push_str(" No address validation detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "data_validation",
                Severity::Medium,
                Category::DataValidation,
                0.8,
                &format!("Data Validation Issue Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add proper data validation including bounds checking, zero value checks, and address validation.",
            ))
        } else {
            None
        }
    }
}

impl Detector for DataValidationDetector {
    fn name(&self) -> &'static str {
        "data_validation"
    }
    fn description(&self) -> &'static str {
        "Detects data validation issues using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::DataValidation
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_data_validation(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 