use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct FlashLoanDetector;

impl FlashLoanDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_flash_loan(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect flash loan-specific issues, not price oracle, reentrancy, or business logic
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_flash_loan_call = false;
        let mut has_atomicity = false;
        let mut has_flash_repay = false;
        let mut has_protection = false;
        let mut flash_loan_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            // Look for flash loan patterns
            if l.contains("flash_loan(") || l.contains("flashBorrow(") || l.contains("atomic_loan(") || l.contains("instant_loan(") {
                found = true;
                has_flash_loan_call = true;
                flash_loan_lines.push(idx + line_number);
            }
            if l.contains("repay(") || l.contains("flashRepay(") {
                has_flash_repay = true;
            }
            if l.contains("atomic") {
                has_atomicity = true;
            }
            // Look for protections specific to flash loans
            if l.contains("reentrancy_guard") || l.contains("flash_loan_protection") || l.contains("cooldown") || l.contains("rate_limit") {
                has_protection = true;
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
        if found && has_flash_loan_call && (!has_protection || called_by_public) {
            let mut description = format!("Function '{}' contains a flash loan operation.", function.name);
            if !has_protection {
                description.push_str(" No flash loan-specific protection detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            if !has_flash_repay {
                description.push_str(" No explicit flash loan repayment detected.");
            }
            if !has_atomicity {
                description.push_str(" No atomicity/transaction boundary detected.");
            }
            Some(Finding::new(
                "flash_loan_attacks",
                Severity::High,
                Category::Security,
                0.9,
                &format!("Flash Loan Vulnerability Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add flash loan-specific protections (reentrancy guard, cooldown, rate limit, atomicity checks, explicit repayment).",
            ))
        } else {
            None
        }
    }
}

impl Detector for FlashLoanDetector {
    fn name(&self) -> &'static str {
        "flash_loan_attacks"
    }
    fn description(&self) -> &'static str {
        "Detects potential flash loan attack vulnerabilities using advanced AST-based analysis."
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
                if let Some(finding) = self.analyze_function_flash_loan(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 