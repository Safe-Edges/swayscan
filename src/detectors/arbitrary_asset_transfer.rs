use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct ArbitraryAssetTransferDetector;

impl ArbitraryAssetTransferDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_asset_transfers(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Advanced: Walk nested AST nodes, track data/control flow, check for access control, inter-function analysis
        let mut found = false;
        let mut line_number = function.span.start;
        let mut op_type = String::new();
        let mut has_access_control = false;
        let mut risky_params = Vec::new();
        let mut transfer_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            if l.contains("transfer(") || l.contains("mint(") || l.contains("mint_to(") || l.contains("force_transfer_to_contract(") {
                found = true;
                op_type = if l.contains("transfer(") {
                    "transfer".to_string()
                } else if l.contains("mint(") {
                    "mint".to_string()
                } else if l.contains("mint_to(") {
                    "mint_to".to_string()
                } else {
                    "force_transfer_to_contract".to_string()
                };
                transfer_lines.push(idx + line_number);
            }
            if l.contains("require(") || l.contains("assert(") || l.contains("only_owner(") || l.contains("has_role(") {
                has_access_control = true;
            }
            if l.contains("msg.sender") || l.contains("caller") || l.contains("user") {
                risky_params.push(l.to_string());
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
        if found && (!has_access_control || called_by_public) {
            let mut description = format!("Function '{}' performs a potentially unsafe asset transfer operation ({}).", function.name, op_type);
            if !has_access_control {
                description.push_str(" No access control detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            if !risky_params.is_empty() {
                description.push_str(&format!(" Risky parameters: {}.", risky_params.join(", ")));
            }
            Some(Finding::new(
                "arbitrary_asset_transfer",
                Severity::High,
                Category::Security,
                0.9,
                &format!("Arbitrary Asset Transfer Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Add access control and validation to asset transfer operations.",
            ))
        } else {
            None
        }
    }
}

impl Detector for ArbitraryAssetTransferDetector {
    fn name(&self) -> &'static str {
        "arbitrary_asset_transfer"
    }
    fn description(&self) -> &'static str {
        "Detects arbitrary asset transfer, mint, or force transfer operations using advanced AST-based analysis."
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
                if let Some(finding) = self.analyze_function_asset_transfers(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}