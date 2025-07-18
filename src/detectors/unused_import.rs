use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct UnusedImportDetector {
    findings: Vec<Finding>,
}

impl UnusedImportDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for UnusedImportDetector {
    fn name(&self) -> &'static str {
        "unused_import"
    }
    
    fn description(&self) -> &'static str {
        "Checks for imported symbols that are not used"
    }
    
    fn severity(&self) -> Severity {
        Severity::Low
    }
    
    fn reset(&mut self) {
        self.findings.clear();
    }
    
    fn findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
}

impl AstVisitor for UnusedImportDetector {}