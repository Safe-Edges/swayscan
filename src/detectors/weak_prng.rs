use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct WeakPrngDetector {
    findings: Vec<Finding>,
}

impl WeakPrngDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for WeakPrngDetector {
    fn name(&self) -> &'static str {
        "weak_prng"
    }
    
    fn description(&self) -> &'static str {
        "Checks for weak PRNG due to a modulo operation on a block timestamp"
    }
    
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn reset(&mut self) {
        self.findings.clear();
    }
    
    fn findings(&self) -> Vec<Finding> {
        self.findings.clone()
    }
}

impl AstVisitor for WeakPrngDetector {}