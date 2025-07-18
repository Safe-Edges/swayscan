use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct StrictEqualityDetector {
    findings: Vec<Finding>,
}

impl StrictEqualityDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for StrictEqualityDetector {
    fn name(&self) -> &'static str {
        "strict_equality"
    }
    
    fn description(&self) -> &'static str {
        "Checks for the use of strict equalities, which can be manipulated by an attacker"
    }
    
    fn severity(&self) -> Severity {
        Severity::High
    }
    
    fn reset(&mut self) {
        self.findings.clear();
    }
    
    fn findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
}

impl AstVisitor for StrictEqualityDetector {}