use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct LockedNativeAssetDetector;

impl LockedNativeAssetDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_locked_native_asset(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect locked native asset-specific issues, not business logic, access control, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_native_asset = false;
        let mut has_withdrawal_mechanism = false;
        let mut has_emergency_exit = false;
        let mut asset_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for native asset operations
            if l.contains("native_asset") || l.contains("base_asset") || l.contains("fuel") {
                has_native_asset = true;
                asset_lines.push(idx + line_number);
            }
            
            // Check for withdrawal mechanisms
            if l.contains("withdraw") || l.contains("emergency_withdraw") || l.contains("exit") {
                has_withdrawal_mechanism = true;
            }
            
            // Check for emergency exit
            if l.contains("emergency") && (l.contains("exit") || l.contains("withdraw")) {
                has_emergency_exit = true;
            }
            
            // Check for locked assets without withdrawal
            if l.contains("lock") || l.contains("stake") || l.contains("deposit") {
                if !l.contains("withdraw") && !l.contains("unlock") {
                    found = true;
                }
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
        
        if found && has_native_asset && (!has_withdrawal_mechanism || !has_emergency_exit || called_by_public) {
            let mut description = format!("Function '{}' contains locked native assets.", function.name);
            if !has_withdrawal_mechanism {
                description.push_str(" No withdrawal mechanism detected.");
            }
            if !has_emergency_exit {
                description.push_str(" No emergency exit mechanism detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "locked_native_asset",
                Severity::High,
                Category::Security,
                0.8,
                &format!("Locked Native Asset Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add withdrawal mechanisms and emergency exit functions for locked native assets.",
            ))
        } else {
            None
        }
    }
}

impl Detector for LockedNativeAssetDetector {
    fn name(&self) -> &'static str {
        "locked_native_asset"
    }
    fn description(&self) -> &'static str {
        "Detects locked native assets without proper withdrawal mechanisms using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Security
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_locked_native_asset(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}