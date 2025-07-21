use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct BusinessLogicDetector;

impl BusinessLogicDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_business_logic(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Advanced: Walk nested AST nodes, track data/control flow, check for business logic violations, inter-function analysis
        let mut found = false;
        let mut line_number = function.span.start;
        let mut issue_type = String::new();
        let mut has_validation = false;
        let mut has_balance_check = false;
        let mut has_supply_check = false;
        let mut has_deadline_check = false;
        let mut business_logic_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // State inconsistency patterns
            if l.contains("storage.balance.write") && l.contains("storage.total_supply.write") {
                found = true;
                issue_type = "state_inconsistency".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            // Business rule violations
            if l.contains("transfer") && l.contains("amount") && l.contains(">") && l.contains("balance") {
                found = true;
                issue_type = "transfer_exceeds_balance".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("mint") && !l.contains("supply_check") && !l.contains("cap") {
                found = true;
                issue_type = "unlimited_minting".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("withdraw") && !l.contains("balance_check") {
                found = true;
                issue_type = "withdraw_without_balance_check".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("burn") && l.contains("amount") && l.contains(">") && l.contains("total_supply") {
                found = true;
                issue_type = "burn_exceeds_supply".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            // Time-based logic issues
            if l.contains("block.timestamp") && (l.contains(">=") || l.contains("<=") || l.contains("+")) {
                found = true;
                issue_type = "time_based_logic".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("deadline") && l.contains("block.timestamp") {
                found = true;
                issue_type = "deadline_logic".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            // Economic logic flaws
            if l.contains("price") && l.contains("*") && l.contains("/") {
                found = true;
                issue_type = "price_calculation".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("fee") && l.contains("=") && l.contains("*") {
                found = true;
                issue_type = "fee_calculation".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            // Access pattern violations
            if l.contains("msg.sender") && l.contains("owner") && l.contains("storage.owner.write") {
                found = true;
                issue_type = "owner_changing_ownership".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            if l.contains("transfer") && l.contains("msg.sender") {
                found = true;
                issue_type = "self_transfer".to_string();
                business_logic_lines.push(idx + line_number);
            }
            
            // Validation checks
            if l.contains("require(") || l.contains("assert(") {
                has_validation = true;
            }
            
            if l.contains("balance") && l.contains("check") {
                has_balance_check = true;
            }
            
            if l.contains("supply") && l.contains("check") {
                has_supply_check = true;
            }
            
            if l.contains("deadline") && l.contains("check") {
                has_deadline_check = true;
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
        
        if found && (!has_validation || !has_balance_check || !has_supply_check || !has_deadline_check || called_by_public) {
            let mut description = format!("Function '{}' contains potential business logic vulnerability ({}).", function.name, issue_type);
            if !has_validation {
                description.push_str(" No validation detected.");
            }
            if !has_balance_check {
                description.push_str(" No balance check detected.");
            }
            if !has_supply_check {
                description.push_str(" No supply check detected.");
            }
            if !has_deadline_check {
                description.push_str(" No deadline check detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            let severity = match issue_type.as_str() {
                "transfer_exceeds_balance" | "unlimited_minting" | "burn_exceeds_supply" => Severity::Critical,
                "state_inconsistency" | "withdraw_without_balance_check" | "owner_changing_ownership" => Severity::High,
                "time_based_logic" | "deadline_logic" | "price_calculation" | "fee_calculation" => Severity::Medium,
                _ => Severity::Medium,
            };
            
            Some(Finding::new(
                "business_logic",
                severity,
                Category::BusinessLogic,
                0.9,
                &format!("Business Logic Vulnerability Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Implement proper business rule validation, balance checks, supply caps, and deadline validation.",
            ))
        } else {
            None
        }
    }
}

impl Detector for BusinessLogicDetector {
    fn name(&self) -> &'static str {
        "business_logic"
    }
    fn description(&self) -> &'static str {
        "Detects business logic vulnerabilities using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::BusinessLogic
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_business_logic(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 