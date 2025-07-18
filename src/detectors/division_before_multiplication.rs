use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

static DIVISION_MULTIPLICATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Pattern: division followed by multiplication
        Regex::new(r"(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)").unwrap(),
        // Pattern: division assignment followed by multiplication
        Regex::new(r"let\s+\w+\s*=\s*\w+\s*/\s*\w+;\s*.*\*").unwrap(),
        // Pattern: division in calculation with multiplication
        Regex::new(r"(\w+\s*/\s*\w+)\s*[\+\-]\s*(\w+\s*\*\s*\w+)").unwrap(),
    ]
});

pub struct DivisionBeforeMultiplicationDetector;

impl DivisionBeforeMultiplicationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_arithmetic_patterns(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_number = line_num + 1;
            
            // Skip comments and empty lines
            if line.trim().starts_with("//") || line.trim().is_empty() {
                continue;
            }
            
            // Check for division before multiplication patterns
            for pattern in DIVISION_MULTIPLICATION_PATTERNS.iter() {
                if pattern.is_match(line) {
                    // Check if this is in a financial context
                    let is_financial = self.is_financial_context(line) || 
                                     self.is_financial_function(&lines, line_num);
                    
                    let severity = if is_financial {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    
                    let confidence = if is_financial { 0.8 } else { 0.6 };
                    
                    let finding = Finding::new(
                        "division_before_multiplication",
                        severity,
                        Category::Security,
                        confidence,
                        "Division Before Multiplication Precision Loss",
                        format!(
                            "Division operation before multiplication at line {} may cause precision loss. \
                            Consider reordering operations: multiply first, then divide to maintain precision.",
                            line_number
                        ),
                        &file.path,
                        line_number,
                        0,
                        line.trim(),
                        "Reorder arithmetic operations: perform multiplication before division to avoid precision loss. \
                        Example: change (a / b) * c to (a * c) / b"
                    )
                    .with_context(context.clone())
                    .with_cwe(vec![682, 190]) // CWE-682: Incorrect Calculation, CWE-190: Integer Overflow
                    .with_impact(format!(
                        "Precision loss in calculations can lead to {} in financial operations.",
                        if is_financial { "fund loss or incorrect balances" } else { "unexpected results" }
                    ));
                    
                    findings.push(finding);
                }
            }
        }
        
        findings
    }
    
    fn is_financial_context(&self, line: &str) -> bool {
        let financial_keywords = [
            "balance", "amount", "price", "fee", "cost", "value", "supply",
            "mint", "burn", "transfer", "deposit", "withdraw", "stake", "reward",
            "collateral", "debt", "interest", "dividend", "payment"
        ];
        
        let line_lower = line.to_lowercase();
        financial_keywords.iter().any(|&keyword| line_lower.contains(keyword))
    }
    
    fn is_financial_function(&self, lines: &[&str], current_line: usize) -> bool {
        // Look backwards for function declaration
        for i in (0..current_line).rev().take(10) {
            let line = lines[i].trim();
            if line.starts_with("fn ") {
                return self.is_financial_context(line);
            }
            if line.contains('{') && !line.contains("fn ") {
                break;
            }
        }
        false
    }
}

impl Detector for DivisionBeforeMultiplicationDetector {
    fn name(&self) -> &'static str {
        "division_before_multiplication"
    }
    
    fn description(&self) -> &'static str {
        "Detects division operations before multiplications that can result in precision loss"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        Ok(self.analyze_arithmetic_patterns(file, context))
    }
}