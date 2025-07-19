use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct FlashLoanDetector;

// Flash loan patterns
static FLASH_LOAN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)flash_loan\s*\(").unwrap(),
        Regex::new(r"(?i)borrow.*amount.*repay").unwrap(),
        Regex::new(r"(?i)flash.*borrow").unwrap(),
        Regex::new(r"(?i)atomic.*loan").unwrap(),
        Regex::new(r"(?i)instant.*loan").unwrap(),
    ]
});

// Vulnerable operations that can be exploited with flash loans
static VULNERABLE_OPS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)liquidate\s*\(").unwrap(),
        Regex::new(r"(?i)arbitrage\s*\(").unwrap(),
        Regex::new(r"(?i)swap\s*\(").unwrap(),
        Regex::new(r"(?i)price\s*=.*get_price").unwrap(),
        Regex::new(r"(?i)calculate.*ratio").unwrap(),
        Regex::new(r"(?i)collateral.*factor").unwrap(),
    ]
});

// Price dependency patterns
static PRICE_DEPENDENCY: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"get_price\s*\(").unwrap(),
        Regex::new(r"oracle\.[\w\.]*price").unwrap(),
        Regex::new(r"reserve0.*reserve1").unwrap(),
        Regex::new(r"balance.*ratio").unwrap(),
    ]
});

// Insufficient protection patterns
static WEAK_PROTECTION: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*msg\.sender\s*==").unwrap(), // Only sender check
        Regex::new(r"assert\s*\(\s*amount\s*>").unwrap(), // Basic amount check
    ]
});

// Strong protection patterns
static STRONG_PROTECTION: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)reentrancy.*guard").unwrap(),
        Regex::new(r"(?i)flash.*loan.*protection").unwrap(),
        Regex::new(r"(?i)time.*delay").unwrap(),
        Regex::new(r"(?i)cooldown").unwrap(),
        Regex::new(r"(?i)rate.*limit").unwrap(),
        Regex::new(r"(?i)oracle.*deviation").unwrap(),
        Regex::new(r"(?i)multi.*block").unwrap(),
    ]
});

impl FlashLoanDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_flash_loan_usage(&self, content: &str) -> Vec<(usize, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            for pattern in FLASH_LOAN_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string()));
                }
            }
        }
        findings
    }

    fn find_vulnerable_operations(&self, content: &str, flash_loan_line: usize) -> Vec<(usize, String)> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        // Look for vulnerable operations within the same function or transaction
        let start = flash_loan_line.saturating_sub(1);
        let end = (start + 20).min(lines.len()); // Check next 20 lines
        
        for (i, line) in lines.iter().enumerate().take(end).skip(start) {
            for pattern in VULNERABLE_OPS.iter() {
                if let Some(mat) = pattern.find(line) {
                    vulnerabilities.push((i + 1, mat.as_str().to_string()));
                }
            }
        }
        vulnerabilities
    }

    fn has_price_dependency(&self, function_content: &str) -> bool {
        for pattern in PRICE_DEPENDENCY.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_strong_protection(&self, function_content: &str) -> bool {
        for pattern in STRONG_PROTECTION.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_weak_protection_only(&self, function_content: &str) -> bool {
        let has_weak = WEAK_PROTECTION.iter().any(|p| p.is_match(function_content));
        let has_strong = self.has_strong_protection(function_content);
        
        has_weak && !has_strong
    }

    fn extract_function_context(&self, content: &str, line_num: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut start = line_num.saturating_sub(1);
        
        // Find function start
        while start > 0 {
            if lines[start].trim().starts_with("fn ") || lines[start].trim().starts_with("pub fn ") {
                break;
            }
            start -= 1;
        }
        
        // Get extended function content for analysis
        let end = (start + 100).min(lines.len());
        lines[start..end].join("\n")
    }

    fn calculate_flash_loan_risk(&self, function_content: &str, vulnerable_ops: &[(usize, String)]) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk for flash loan + vulnerable operation
        if !vulnerable_ops.is_empty() {
            risk_score += 0.7;
        }
        
        // Higher risk if price-dependent
        if self.has_price_dependency(function_content) {
            risk_score += 0.3;
        }
        
        // Higher risk for liquidation functions
        if function_content.contains("liquidate") {
            risk_score += 0.4;
        }
        
        // Higher risk for arbitrage functions
        if function_content.contains("arbitrage") {
            risk_score += 0.3;
        }
        
        // Higher risk if no multi-block protection
        if !function_content.contains("block") && !function_content.contains("time") {
            risk_score += 0.2;
        }
        
        // Reduce risk if strong protections exist
        if self.has_strong_protection(function_content) {
            risk_score *= 0.3;
        } else if self.has_weak_protection_only(function_content) {
            risk_score *= 0.8; // Slight reduction for weak protection
        }
        
        risk_score.min(1.0)
    }
}

impl Detector for FlashLoanDetector {
    fn name(&self) -> &'static str {
        "flash_loan_attacks"
    }
    
    fn description(&self) -> &'static str {
        "Detects potential flash loan attack vulnerabilities where atomic transactions can be exploited"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find flash loan usage
        let flash_loans = self.find_flash_loan_usage(&file.content);
        
        for (flash_line, _flash_pattern) in flash_loans {
            let function_content = self.extract_function_context(&file.content, flash_line);
            
            // Find vulnerable operations in the same context
            let vulnerable_ops = self.find_vulnerable_operations(&file.content, flash_line);
            
            if !vulnerable_ops.is_empty() {
                let confidence = self.calculate_flash_loan_risk(&function_content, &vulnerable_ops);
                
                if confidence >= 0.7 {
                    let severity = if confidence >= 0.9 {
                        Severity::Critical
                    } else if confidence >= 0.8 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let vulnerable_operations: Vec<String> = vulnerable_ops.iter()
                        .map(|(line, op)| format!("Line {}: {}", line, op))
                        .collect();

                    let mut risk_factors = Vec::new();
                    if self.has_price_dependency(&function_content) {
                        risk_factors.push("Price dependency (oracle manipulation risk)");
                    }
                    if function_content.contains("liquidate") {
                        risk_factors.push("Liquidation function (can be manipulated)");
                    }
                    if function_content.contains("arbitrage") {
                        risk_factors.push("Arbitrage function (MEV vulnerability)");
                    }
                    if !self.has_strong_protection(&function_content) {
                        risk_factors.push("Insufficient protection against atomic attacks");
                    }

                    let finding = Finding::new(
                        self.name(),
                        severity,
                        self.category(),
                        confidence,
                        "Flash Loan Attack Vulnerability",
                        &format!(
                            "Flash loan at line {} combined with vulnerable operations: {}. Risk factors: {}. Attackers can use flash loans to manipulate state atomically and extract value.",
                            flash_line,
                            vulnerable_operations.join(", "),
                            risk_factors.join(", ")
                        ),
                        &file.path,
                        flash_line,
                        1,
                        extract_code_snippet(&file.content, flash_line, 3),
                        "Implement flash loan protections: (1) Multi-block operations to prevent atomic manipulation, (2) Oracle price validation with TWAP, (3) Rate limiting and cooldowns, (4) Reentrancy guards, (5) Deviation checks for price-sensitive operations.",
                    )
                    .with_impact("Critical - Attackers can manipulate protocol state and extract funds through atomic transactions")
                    .with_effort(EstimatedEffort::Hard)
                    .with_cwe(vec![362, 841, 696]) // CWE-362: Race Condition, CWE-841: Improper Behavioral Workflow, CWE-696: Incorrect Behavior Order
                    .with_references(vec![
                        Reference {
                            title: "Flash Loan Attack Prevention".to_string(),
                            url: "https://consensys.github.io/smart-contract-best-practices/attacks/flash-loans/".to_string(),
                            reference_type: ReferenceType::Security,
                        },
                        Reference {
                            title: "Sway Security Guidelines".to_string(),
                            url: "https://docs.fuel.network/docs/sway/advanced/security/".to_string(),
                            reference_type: ReferenceType::Documentation,
                        }
                    ])
                    .with_context(context.clone());
                    
                    findings.push(finding);
                }
            }
        }
        
        Ok(findings)
    }
} 