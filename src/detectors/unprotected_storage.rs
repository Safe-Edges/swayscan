use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet};
use crate::error::SwayscanError;
use crate::parser::SwayFile;

pub struct UnprotectedStorageDetector;

impl UnprotectedStorageDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for UnprotectedStorageDetector {
    fn name(&self) -> &'static str {
        "unprotected_storage_variable"
    }
    
    fn description(&self) -> &'static str {
        "Finds storage modifications without access restrictions"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        for (line_num, line) in file.content.lines().enumerate() {
            if line.contains("storage.") && line.contains(".write(") {
                if !line.contains("require") && !line.contains("assert") && !line.contains("only_owner") {
                    let finding = Finding::new(
                        self.name(),
                        self.default_severity(),
                        self.category(),
                        0.8,
                        "Unprotected Storage Modification",
                        "Storage variable is modified without proper access control",
                        &file.path,
                        line_num + 1,
                        1,
                        extract_code_snippet(&file.content, line_num + 1, 2),
                        "Add access control checks before modifying storage variables",
                    )
                    .with_context(context.clone());
                    
                    findings.push(finding);
                }
            }
        }
        
        Ok(findings)
    }
}