use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct UnprotectedStorageDetector;

impl UnprotectedStorageDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_unprotected_storage(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect unprotected storage-specific issues, not access control, business logic, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_storage_write = false;
        let mut has_access_control = false;
        let mut storage_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            if l.contains("storage.") && l.contains(".write(") {
                has_storage_write = true;
                storage_lines.push(idx + line_number);
            }
            if l.contains("require(") || l.contains("assert(") || l.contains("only_owner(") || l.contains("has_role(") {
                has_access_control = true;
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
        if has_storage_write && (!has_access_control || called_by_public) {
            let mut description = format!("Function '{}' modifies storage without proper access control.", function.name);
            if !has_access_control {
                description.push_str(" No access control detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            Some(Finding::new(
                "unprotected_storage_variable",
                Severity::High,
                Category::Storage,
                0.8,
                &format!("Unprotected Storage Modification Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add access control checks before modifying storage variables.",
            ))
        } else {
            None
        }
    }
}

impl Detector for UnprotectedStorageDetector {
    fn name(&self) -> &'static str {
        "unprotected_storage_variable"
    }
    fn description(&self) -> &'static str {
        "Finds storage modifications without access restrictions using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Storage
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_unprotected_storage(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}