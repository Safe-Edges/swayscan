use crate::detectors::{Detector, Finding, Severity};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, AstVisitor};

pub struct LockedNativeAssetDetector {
    findings: Vec<Finding>,
}

impl LockedNativeAssetDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Detector for LockedNativeAssetDetector {
    fn name(&self) -> &'static str {
        "locked_native_asset"
    }
    
    fn description(&self) -> &'static str {
        "Checks if a contract can withdraw potential incoming native assets"
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

impl AstVisitor for LockedNativeAssetDetector {}