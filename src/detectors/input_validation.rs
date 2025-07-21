use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayFunction, SwayParameter, SwayStatement, StatementKind, SwayExpression, ExpressionKind};
use crate::analyzer::SwayAstAnalyzer;
use std::collections::HashMap;

pub struct InputValidationDetector {
    ast_analyzer: SwayAstAnalyzer,
}

#[derive(Debug, Clone)]
pub struct InputValidationAnalysis {
    pub parameters: Vec<ParameterAnalysis>,
    pub validation_checks: Vec<ValidationCheck>,
    pub risky_operations: Vec<RiskyOperation>,
    pub missing_validations: Vec<MissingValidation>,
    pub risk_patterns: Vec<RiskPattern>,
}

#[derive(Debug, Clone)]
pub struct ParameterAnalysis {
    pub name: String,
    pub type_: String,
    pub line: usize,
    pub is_validated: bool,
    pub validation_type: Option<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub struct ValidationCheck {
    pub line: usize,
    pub check_type: String,
    pub parameter: String,
    pub condition: String,
    pub effectiveness: f64,
}

#[derive(Debug, Clone)]
pub struct RiskyOperation {
    pub line: usize,
    pub operation_type: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub parameters_used: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MissingValidation {
    pub parameter: String,
    pub type_: String,
    pub line: usize,
    pub risk_level: RiskLevel,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct RiskPattern {
    pub pattern_type: String,
    pub severity: Severity,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl InputValidationDetector {
    pub fn new() -> Self {
        Self {
            ast_analyzer: SwayAstAnalyzer::new(),
        }
    }

    fn analyze_function_input_validation(&self, function: &SwayFunction, file: &SwayFile) -> InputValidationAnalysis {
        let mut analysis = InputValidationAnalysis {
            parameters: Vec::new(),
            validation_checks: Vec::new(),
            risky_operations: Vec::new(),
            missing_validations: Vec::new(),
            risk_patterns: Vec::new(),
        };

        // Analyze function parameters
        analysis.parameters = self.analyze_parameters(function);
        
        // Analyze validation checks
        analysis.validation_checks = self.analyze_validation_checks(function);
        
        // Analyze risky operations
        analysis.risky_operations = self.analyze_risky_operations(function);
        
        // Find missing validations
        analysis.missing_validations = self.find_missing_validations(&analysis);
        
        // Analyze risk patterns
        analysis.risk_patterns = self.analyze_risk_patterns(&analysis);
        
        analysis
    }

    fn analyze_parameters(&self, function: &SwayFunction) -> Vec<ParameterAnalysis> {
        let mut parameters = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        // Extract parameters from function signature
        if let Some(param_start) = function.content.find('(') {
            if let Some(param_end) = function.content.find(')') {
                let params_str = &function.content[param_start + 1..param_end];
                let param_list: Vec<&str> = params_str.split(',').collect();
                
                for (i, param) in param_list.iter().enumerate() {
                    let param = param.trim();
                    if !param.is_empty() {
                        if let Some(colon_pos) = param.find(':') {
                            let name = param[..colon_pos].trim().to_string();
                            let type_ = param[colon_pos + 1..].trim().to_string();
                            
                            let risk_level = self.assess_parameter_risk(&type_);
                            let is_validated = self.is_parameter_validated(&name, function);
                            let validation_type = self.get_validation_type(&name, function);
                            
                            parameters.push(ParameterAnalysis {
                                name: name.clone(),
                                type_,
                                line: self.find_parameter_line(&lines, &name),
                                is_validated,
                                validation_type,
                                risk_level,
                            });
                        }
                    }
                }
            }
        }
        
        parameters
    }

    fn analyze_validation_checks(&self, function: &SwayFunction) -> Vec<ValidationCheck> {
        let mut checks = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            let line = line.trim();
            
            // Detect require statements
            if line.contains("require(") {
                if let Some(check) = self.parse_require_statement(line, i + 1) {
                    checks.push(check);
                }
            }
            
            // Detect assert statements
            if line.contains("assert(") {
                if let Some(check) = self.parse_assert_statement(line, i + 1) {
                    checks.push(check);
                }
            }
            
            // Detect conditional checks
            if line.contains("if ") && line.contains("revert") {
                if let Some(check) = self.parse_conditional_check(line, i + 1) {
                    checks.push(check);
                }
            }
        }
        
        checks
    }

    fn analyze_risky_operations(&self, function: &SwayFunction) -> Vec<RiskyOperation> {
        let mut operations = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            let line = line.trim();
            
            // Financial operations
            if line.contains("transfer(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "asset_transfer".to_string(),
                    description: "Asset transfer operation".to_string(),
                    risk_level: RiskLevel::High,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
            
            if line.contains("mint_to(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "token_minting".to_string(),
                    description: "Token minting operation".to_string(),
                    risk_level: RiskLevel::Critical,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
            
            if line.contains("burn(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "token_burning".to_string(),
                    description: "Token burning operation".to_string(),
                    risk_level: RiskLevel::High,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
            
            // Storage operations
            if line.contains("storage.") && line.contains(".write(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "storage_write".to_string(),
                    description: "Storage write operation".to_string(),
                    risk_level: RiskLevel::Medium,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
            
            if line.contains("storage.") && line.contains(".insert(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "storage_insert".to_string(),
                    description: "Storage insert operation".to_string(),
                    risk_level: RiskLevel::Medium,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
            
            // External calls
            if line.contains("abi(") || line.contains("contract_call(") {
                operations.push(RiskyOperation {
                    line: i + 1,
                    operation_type: "external_call".to_string(),
                    description: "External contract call".to_string(),
                    risk_level: RiskLevel::High,
                    parameters_used: self.extract_parameters_from_line(line),
                });
            }
        }
        
        operations
    }

    fn find_missing_validations(&self, analysis: &InputValidationAnalysis) -> Vec<MissingValidation> {
        let mut missing = Vec::new();
        
        for param in &analysis.parameters {
            if !param.is_validated && param.risk_level != RiskLevel::Low {
                let description = match param.risk_level {
                    RiskLevel::Critical => format!("Critical parameter '{}' of type '{}' has no validation", param.name, param.type_),
                    RiskLevel::High => format!("High-risk parameter '{}' of type '{}' lacks validation", param.name, param.type_),
                    RiskLevel::Medium => format!("Medium-risk parameter '{}' of type '{}' needs validation", param.name, param.type_),
                    RiskLevel::Low => continue,
                };
                
                missing.push(MissingValidation {
                    parameter: param.name.clone(),
                    type_: param.type_.clone(),
                    line: param.line,
                    risk_level: param.risk_level.clone(),
                    description,
                });
            }
        }
        
        missing
    }

    fn analyze_risk_patterns(&self, analysis: &InputValidationAnalysis) -> Vec<RiskPattern> {
        let mut patterns = Vec::new();
        
        // Pattern 1: Financial operations without validation
        let financial_ops: Vec<_> = analysis.risky_operations.iter()
            .filter(|op| op.operation_type.contains("transfer") || op.operation_type.contains("mint"))
            .collect();
        
        if !financial_ops.is_empty() && analysis.missing_validations.iter().any(|v| v.risk_level == RiskLevel::Critical) {
            patterns.push(RiskPattern {
                pattern_type: "financial_operations_no_validation".to_string(),
                severity: Severity::Critical,
                description: "Financial operations performed without input validation".to_string(),
                confidence: 0.9,
            });
        }
        
        // Pattern 2: Storage operations with unvalidated parameters
        let storage_ops: Vec<_> = analysis.risky_operations.iter()
            .filter(|op| op.operation_type.contains("storage"))
            .collect();
        
        if !storage_ops.is_empty() && analysis.missing_validations.iter().any(|v| v.risk_level == RiskLevel::High) {
            patterns.push(RiskPattern {
                pattern_type: "storage_operations_no_validation".to_string(),
                severity: Severity::High,
                description: "Storage operations performed without parameter validation".to_string(),
                confidence: 0.8,
            });
        }
        
        // Pattern 3: External calls with unvalidated parameters
        let external_calls: Vec<_> = analysis.risky_operations.iter()
            .filter(|op| op.operation_type.contains("external"))
            .collect();
        
        if !external_calls.is_empty() && analysis.missing_validations.iter().any(|v| v.risk_level == RiskLevel::High) {
            patterns.push(RiskPattern {
                pattern_type: "external_calls_no_validation".to_string(),
                severity: Severity::High,
                description: "External calls made with unvalidated parameters".to_string(),
                confidence: 0.85,
            });
        }
        
        patterns
    }

    fn assess_parameter_risk(&self, type_: &str) -> RiskLevel {
        match type_ {
            "u64" | "u32" | "u16" | "u8" => RiskLevel::Medium,
            "Identity" | "Address" => RiskLevel::High,
            "AssetId" | "ContractId" => RiskLevel::High,
            "b256" => RiskLevel::Medium,
            "Vec<u8>" | "Vec<u64>" => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }

    fn is_parameter_validated(&self, param_name: &str, function: &SwayFunction) -> bool {
        let content = &function.content;
        
        // Check for require statements
        if content.contains(&format!("require({}", param_name)) {
            return true;
        }
        
        // Check for zero address validation
        if content.contains(&format!("{} != Address::zero()", param_name)) {
            return true;
        }
        
        // Check for range validation
        if content.contains(&format!("{} > 0", param_name)) || 
           content.contains(&format!("{} >= 0", param_name)) {
            return true;
        }
        
        // Check for bounds validation
        if content.contains(&format!("{} < ", param_name)) || 
           content.contains(&format!("{} <= ", param_name)) {
            return true;
        }
        
        false
    }

    fn get_validation_type(&self, param_name: &str, function: &SwayFunction) -> Option<String> {
        let content = &function.content;
        
        if content.contains(&format!("require({}", param_name)) {
            Some("require_check".to_string())
        } else if content.contains(&format!("{} != Address::zero()", param_name)) {
            Some("zero_address_check".to_string())
        } else if content.contains(&format!("{} > 0", param_name)) {
            Some("positive_value_check".to_string())
        } else if content.contains(&format!("{} < ", param_name)) {
            Some("upper_bound_check".to_string())
        } else {
            None
        }
    }

    fn parse_require_statement(&self, line: &str, line_num: usize) -> Option<ValidationCheck> {
        // Simple parsing of require statements
        if let Some(start) = line.find("require(") {
            if let Some(end) = line.rfind(')') {
                let condition = line[start + 8..end].trim();
                return Some(ValidationCheck {
                    line: line_num,
                    check_type: "require".to_string(),
                    parameter: self.extract_parameter_from_condition(condition),
                    condition: condition.to_string(),
                    effectiveness: 0.9,
                });
            }
        }
        None
    }

    fn parse_assert_statement(&self, line: &str, line_num: usize) -> Option<ValidationCheck> {
        if let Some(start) = line.find("assert(") {
            if let Some(end) = line.rfind(')') {
                let condition = line[start + 7..end].trim();
                return Some(ValidationCheck {
                    line: line_num,
                    check_type: "assert".to_string(),
                    parameter: self.extract_parameter_from_condition(condition),
                    condition: condition.to_string(),
                    effectiveness: 0.8,
                });
            }
        }
        None
    }

    fn parse_conditional_check(&self, line: &str, line_num: usize) -> Option<ValidationCheck> {
        if line.contains("if ") && line.contains("revert") {
            return Some(ValidationCheck {
                line: line_num,
                check_type: "conditional_revert".to_string(),
                parameter: "unknown".to_string(),
                condition: line.to_string(),
                effectiveness: 0.7,
            });
        }
        None
    }

    fn extract_parameter_from_condition(&self, condition: &str) -> String {
        // Simple extraction - look for variable names
        let parts: Vec<&str> = condition.split_whitespace().collect();
        for part in parts {
            if part.chars().all(|c| c.is_alphanumeric() || c == '_') && !part.is_empty() {
                return part.to_string();
            }
        }
        "unknown".to_string()
    }

    fn extract_parameters_from_line(&self, line: &str) -> Vec<String> {
        let mut params = Vec::new();
        
        // Extract parameters from function calls
        if let Some(start) = line.find('(') {
            if let Some(end) = line.rfind(')') {
                let args_str = &line[start + 1..end];
                let args: Vec<&str> = args_str.split(',').collect();
                
                for arg in args {
                    let arg = arg.trim();
                    if !arg.is_empty() {
                        // Extract variable names from arguments
                        if let Some(var_name) = self.extract_variable_name(arg) {
                            params.push(var_name);
                        }
                    }
                }
            }
        }
        
        params
    }

    fn extract_variable_name(&self, arg: &str) -> Option<String> {
        // Simple variable name extraction
        let arg = arg.trim();
        if arg.chars().all(|c| c.is_alphanumeric() || c == '_') && !arg.is_empty() {
            Some(arg.to_string())
        } else {
            None
        }
    }

    fn find_parameter_line(&self, lines: &[&str], param_name: &str) -> usize {
        for (i, line) in lines.iter().enumerate() {
            if line.contains(param_name) && line.contains(':') {
                return i + 1;
            }
        }
        1
    }

    fn create_detailed_description(&self, analysis: &InputValidationAnalysis, function: &SwayFunction) -> String {
        let mut description = format!(
            "Function '{}' has insufficient input validation. ",
            function.name
        );
        
        // Add parameter details
        let unvalidated_params: Vec<_> = analysis.parameters.iter()
            .filter(|p| !p.is_validated && p.risk_level != RiskLevel::Low)
            .collect();
        
        if !unvalidated_params.is_empty() {
            let param_names: Vec<String> = unvalidated_params.iter()
                .map(|p| format!("{} ({})", p.name, p.type_))
                .collect();
            description.push_str(&format!("Unvalidated parameters: {}. ", param_names.join(", ")));
        }
        
        // Add risky operations
        if !analysis.risky_operations.is_empty() {
            let op_types: Vec<String> = analysis.risky_operations.iter()
                .map(|op| op.operation_type.clone())
                .collect();
            description.push_str(&format!("Risky operations detected: {}. ", op_types.join(", ")));
        }
        
        // Add risk patterns
        if !analysis.risk_patterns.is_empty() {
            let pattern_descriptions: Vec<String> = analysis.risk_patterns.iter()
                .map(|p| p.description.clone())
                .collect();
            description.push_str(&format!("Risk patterns: {}. ", pattern_descriptions.join("; ")));
        }
        
        description
    }

    fn calculate_severity(&self, analysis: &InputValidationAnalysis) -> Severity {
        let critical_count = analysis.missing_validations.iter()
            .filter(|v| v.risk_level == RiskLevel::Critical)
            .count();
        
        let high_count = analysis.missing_validations.iter()
            .filter(|v| v.risk_level == RiskLevel::High)
            .count();
        
        if critical_count > 0 {
            Severity::Critical
        } else if high_count > 0 {
            Severity::High
        } else {
            Severity::Medium
        }
    }

    fn calculate_confidence(&self, analysis: &InputValidationAnalysis) -> f64 {
        let mut confidence = 0.5; // Base confidence
        
        // Higher confidence for critical missing validations
        let critical_missing = analysis.missing_validations.iter()
            .filter(|v| v.risk_level == RiskLevel::Critical)
            .count();
        confidence += critical_missing as f64 * 0.2;
        
        // Higher confidence for financial operations
        let financial_ops = analysis.risky_operations.iter()
            .filter(|op| op.operation_type.contains("transfer") || op.operation_type.contains("mint"))
            .count();
        confidence += financial_ops as f64 * 0.15;
        
        // Reduce confidence if some validation exists
        let validated_params = analysis.parameters.iter()
            .filter(|p| p.is_validated)
            .count();
        confidence -= validated_params as f64 * 0.1;
        
        confidence.min(1.0).max(0.0)
    }
}

impl Detector for InputValidationDetector {
    fn name(&self) -> &'static str {
        "input_validation_detector"
    }
    
    fn description(&self) -> &'static str {
        "Advanced AST-based input validation detector for Sway smart contracts"
    }
    
    fn category(&self) -> Category {
        Category::InputValidation
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                // Skip view functions and test functions
                if function.visibility == crate::parser::FunctionVisibility::Public && 
                   function.content.contains("#[storage(read)]") {
                    continue;
                }
                
                if function.name.starts_with("test_") {
                    continue;
                }
                
                // Perform comprehensive input validation analysis
                let analysis = self.analyze_function_input_validation(function, file);
                
                // Only create findings if there are missing validations
                if !analysis.missing_validations.is_empty() {
                    let severity = self.calculate_severity(&analysis);
                    let confidence = self.calculate_confidence(&analysis);
                    
                    // Only report if confidence is above threshold
                    if confidence >= 0.6 {
                        let description = self.create_detailed_description(&analysis, function);
                        
                        // Find the actual line number where this function starts
                        let line_number = self.find_function_line_number(&file.content, &function.name);
                        let code_at_line = self.extract_code_at_line(&file.content, line_number);
                        
                        let title = format!("Insufficient Input Validation - {}", function.name);
                        
                        let finding = Finding::new(
                            self.name(),
                            severity,
                            Category::InputValidation,
                            confidence,
                            &title,
                            &description,
                            &file.path,
                            line_number,
                            line_number,
                            &code_at_line,
                            &format!("Implement comprehensive input validation for function '{}': (1) Add require() statements for parameter bounds, (2) Check for zero addresses/IDs, (3) Validate ranges before arithmetic operations, (4) Use checked arithmetic for financial calculations.", function.name),
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![20, 129, 190]) // Improper Input Validation, Improper Validation of Array Index, Integer Overflow
                        .with_effort(EstimatedEffort::Easy)
                        .with_references(vec![
                            Reference {
                                title: "OWASP Input Validation Cheat Sheet".to_string(),
                                url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html".to_string(),
                                reference_type: ReferenceType::Security,
                            },
                        ]);
                        
                        findings.push(finding);
                    }
                }
            }
        }
        
        Ok(findings)
    }
}

impl InputValidationDetector {
    fn find_function_line_number(&self, content: &str, function_name: &str) -> usize {
        let lines: Vec<&str> = content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("fn {}", function_name)) || 
               line.contains(&format!("pub fn {}", function_name)) {
                return i + 1;
            }
        }
        
        1 // Default to first line if not found
    }
    
    fn extract_code_at_line(&self, content: &str, line_number: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        
        if line_number <= lines.len() {
            lines[line_number - 1].to_string()
        } else {
            String::new()
        }
    }
} 