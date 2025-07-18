use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct BooleanComparisonDetector {
    findings: Vec<Finding>,
}

impl BooleanComparisonDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for BooleanComparisonDetector {
    fn name(&self) -> &'static str {
        "boolean_comparison"
    }
    
    fn description(&self) -> &'static str {
        "Checks if an expression contains a comparison with a boolean literal, which is unnecessary"
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

impl AstVisitor for BooleanComparisonDetector {}