use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct ExternalCallInLoopDetector {
    findings: Vec<Finding>,
}

impl ExternalCallInLoopDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for ExternalCallInLoopDetector {
    fn name(&self) -> &'static str {
        "external_call_in_loop"
    }
    
    fn description(&self) -> &'static str {
        "Checks if any functions contain any loops which performs calls to external functions"
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

impl AstVisitor for ExternalCallInLoopDetector {}