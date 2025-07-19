use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct PriceOracleDetector;

// Oracle call patterns in Sway/Fuel
static ORACLE_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)get_price\s*\(").unwrap(),
        Regex::new(r"(?i)price_feed\s*\(").unwrap(),
        Regex::new(r"(?i)oracle\.[\w\.]*price").unwrap(),
        Regex::new(r"(?i)chainlink\s*\(").unwrap(),
        Regex::new(r"(?i)get_latest_round_data\s*\(").unwrap(),
        Regex::new(r"(?i)get_asset_price\s*\(").unwrap(),
        Regex::new(r"(?i)price_oracle\s*\(").unwrap(),
    ]
});

// Single oracle dependency patterns (risky)
static SINGLE_ORACLE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"let\s+\w*price\w*\s*=\s*\w+\.get_price\s*\([^)]*\)\s*;").unwrap(),
        Regex::new(r"let\s+\w+\s*=\s*oracle\.[\w\.]*price\s*\([^)]*\)\s*;").unwrap(),
    ]
});

// Direct price usage without validation
static DIRECT_PRICE_USAGE: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?m)^\s*let\s+\w*price\w*.*=.*get_price.*;\s*$\s*.*price\w*\s*[\*/]").unwrap(),
        Regex::new(r"return.*price\w*\s*[\*/]").unwrap(),
        Regex::new(r"storage\.[\w\.]*\.write\([^)]*price\w*\s*[\*/]").unwrap(),
    ]
});

// Price validation patterns (protective)
static PRICE_VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*price\w*\s*>\s*\d+").unwrap(),
        Regex::new(r"assert\s*\(\s*price\w*\s*[><!]=").unwrap(),
        Regex::new(r"if\s+price\w*\s*[<>=!].*\{[^}]*revert").unwrap(),
        Regex::new(r"price\w*\s*[<>=!].*&&.*timestamp").unwrap(),
        Regex::new(r"multiple.*oracle").unwrap(),
        Regex::new(r"average.*price").unwrap(),
        Regex::new(r"price.*deviation").unwrap(),
        Regex::new(r"price.*staleness").unwrap(),
    ]
});

// Flash loan patterns that can manipulate price
static FLASH_LOAN_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)flash_loan\s*\(").unwrap(),
        Regex::new(r"(?i)borrow.*repay").unwrap(),
        Regex::new(r"(?i)flash.*borrow").unwrap(),
    ]
});

// DEX manipulation patterns
static DEX_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)swap\s*\(").unwrap(),
        Regex::new(r"(?i)liquidity\s*\(").unwrap(),
        Regex::new(r"(?i)reserve").unwrap(),
        Regex::new(r"(?i)pool\.[\w\.]*balance").unwrap(),
    ]
});

impl PriceOracleDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_oracle_calls(&self, content: &str) -> Vec<(usize, String)> {
        let mut calls = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            for pattern in ORACLE_CALL_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    calls.push((i + 1, mat.as_str().to_string()));
                }
            }
        }
        calls
    }

    fn has_single_oracle_dependency(&self, content: &str) -> Vec<(usize, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            for pattern in SINGLE_ORACLE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string()));
                }
            }
        }
        findings
    }

    fn has_direct_price_usage(&self, content: &str, oracle_line: usize) -> Vec<(usize, String)> {
        let mut usages = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        // Look for price usage in the next 10 lines after oracle call
        let start = oracle_line.saturating_sub(1);
        let end = (start + 10).min(lines.len());
        
        for (i, line) in lines.iter().enumerate().take(end).skip(start) {
            for pattern in DIRECT_PRICE_USAGE.iter() {
                if pattern.is_match(line) {
                    usages.push((i + 1, line.to_string()));
                }
            }
        }
        usages
    }

    fn has_price_validation(&self, function_content: &str) -> bool {
        for pattern in PRICE_VALIDATION_PATTERNS.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_flash_loan_context(&self, function_content: &str) -> bool {
        for pattern in FLASH_LOAN_PATTERNS.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
    }

    fn has_dex_interaction(&self, function_content: &str) -> bool {
        for pattern in DEX_PATTERNS.iter() {
            if pattern.is_match(function_content) {
                return true;
            }
        }
        false
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
        
        // Get function content (up to 50 lines)
        let end = (start + 50).min(lines.len());
        lines[start..end].join("\n")
    }

    fn calculate_risk_score(&self, function_content: &str, has_direct_usage: bool, has_validation: bool) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk for oracle usage without validation
        if !has_validation {
            risk_score += 0.6;
        }
        
        // Higher risk for direct price usage
        if has_direct_usage {
            risk_score += 0.3;
        }
        
        // Much higher risk if combined with flash loans
        if self.has_flash_loan_context(function_content) {
            risk_score += 0.4;
        }
        
        // Higher risk if combined with DEX interactions
        if self.has_dex_interaction(function_content) {
            risk_score += 0.2;
        }
        
        // Financial operations increase risk
        if function_content.contains("transfer") || function_content.contains("mint") || function_content.contains("liquidate") {
            risk_score += 0.2;
        }
        
        // Reduce risk if multiple validation mechanisms
        let validation_count = PRICE_VALIDATION_PATTERNS.iter()
            .filter(|pattern| pattern.is_match(function_content))
            .count();
        
        if validation_count >= 2 {
            risk_score *= 0.4;
        } else if validation_count == 1 {
            risk_score *= 0.7;
        }
        
        risk_score.min(1.0)
    }
}

impl Detector for PriceOracleDetector {
    fn name(&self) -> &'static str {
        "price_oracle_manipulation"
    }
    
    fn description(&self) -> &'static str {
        "Detects potential price oracle manipulation vulnerabilities where price feeds can be manipulated by attackers"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        // Find all oracle calls
        let oracle_calls = self.find_oracle_calls(&file.content);
        
        for (oracle_line, _oracle_pattern) in oracle_calls {
            let function_content = self.extract_function_context(&file.content, oracle_line);
            
            // Check for risky patterns
            let single_oracle = self.has_single_oracle_dependency(&function_content);
            let direct_usage = self.has_direct_price_usage(&file.content, oracle_line);
            let has_validation = self.has_price_validation(&function_content);
            
            // Calculate risk
            let confidence = self.calculate_risk_score(&function_content, !direct_usage.is_empty(), has_validation);
            
            // Report high-confidence findings
            if confidence >= 0.7 {
                let severity = if confidence >= 0.9 {
                    Severity::Critical
                } else if confidence >= 0.8 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut risk_factors = Vec::new();
                if !single_oracle.is_empty() {
                    risk_factors.push("Single oracle dependency");
                }
                if !direct_usage.is_empty() {
                    risk_factors.push("Direct price usage without validation");
                }
                if self.has_flash_loan_context(&function_content) {
                    risk_factors.push("Flash loan context (high manipulation risk)");
                }
                if self.has_dex_interaction(&function_content) {
                    risk_factors.push("DEX interaction (price manipulation possible)");
                }
                if !has_validation {
                    risk_factors.push("Missing price validation/staleness checks");
                }

                let finding = Finding::new(
                    self.name(),
                    severity,
                    self.category(),
                    confidence,
                    "Price Oracle Manipulation Vulnerability",
                    &format!(
                        "Price oracle at line {} is vulnerable to manipulation. Risk factors: {}. Attackers can manipulate oracle prices through flash loans, MEV, or oracle front-running.",
                        oracle_line,
                        risk_factors.join(", ")
                    ),
                    &file.path,
                    oracle_line,
                    1,
                    extract_code_snippet(&file.content, oracle_line, 3),
                    "Implement multiple price validation mechanisms: (1) Use multiple independent oracles, (2) Add price deviation checks, (3) Implement staleness validation, (4) Use time-weighted average prices (TWAP), (5) Add circuit breakers for extreme price movements.",
                )
                .with_impact("Critical - Attackers can manipulate prices to extract funds, cause unfair liquidations, or break protocol economics")
                .with_effort(EstimatedEffort::Hard)
                .with_cwe(vec![20, 345, 400]) // CWE-20: Input Validation, CWE-345: Insufficient Verification of Data Authenticity, CWE-400: Resource Consumption
                .with_references(vec![
                    Reference {
                        title: "Oracle Manipulation Attacks".to_string(),
                        url: "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/".to_string(),
                        reference_type: ReferenceType::Security,
                    },
                    Reference {
                        title: "Fuel Network Oracle Security".to_string(),
                        url: "https://docs.fuel.network/docs/sway/advanced/security/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    }
                ])
                .with_context(context.clone());
                
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }
} 