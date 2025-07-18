use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct MissingLogsDetector {
    findings: Vec<Finding>,
}

impl MissingLogsDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for MissingLogsDetector {
    fn name(&self) -> &'static str {
        "missing_logs"
    }
    
    fn description(&self) -> &'static str {
        "Checks for publicly-accessible functions that make changes to storage variables without emitting logs"
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

impl AstVisitor for MissingLogsDetector {}