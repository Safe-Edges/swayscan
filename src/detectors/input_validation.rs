use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct InputValidationDetector;

// Advanced Analysis Structures for Input Validation
#[derive(Debug, Clone)]
struct InputValidationFCG {
    callers: HashMap<String, HashSet<String>>,
    callees: HashMap<String, HashSet<String>>,
    function_signatures: HashMap<String, InputValidationSignature>,
}

#[derive(Debug, Clone)]
struct InputValidationSignature {
    name: String,
    line_start: usize,
    line_end: usize,
    parameters: Vec<String>,
    parameter_types: HashMap<String, String>,
    has_validation: bool,
    validation_context: Vec<String>,
    risk_level: RiskLevel,
    called_by_validated_functions: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct InputValidationPPL {
    validated_functions: HashSet<String>,
    validation_sources: HashMap<String, Vec<String>>,
    propagation_paths: HashMap<String, Vec<String>>,
    validation_strength: HashMap<String, ValidationStrength>,
}

#[derive(Debug, Clone, PartialEq)]
enum ValidationStrength {
    Weak,    // Basic checks
    Medium,  // Boundary checks
    Strong,  // Comprehensive validation
    Robust,  // Multiple validation layers
}

#[derive(Debug, Clone)]
struct InputValidationPDG {
    parameter_flows: HashMap<String, Vec<String>>,
    validation_dependencies: HashMap<String, Vec<String>>,
    risk_parameters: HashSet<String>,
    validation_coverage: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct InputValidationCVC {
    valid_contexts: HashSet<String>,
    context_rules: HashMap<String, Vec<String>>,
    validation_results: HashMap<String, bool>,
    false_positive_filters: HashSet<String>,
}

// Function parameters that need validation - more robust patterns
static RISKY_PARAMETER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*u\d+)[^)]*\)").unwrap(), // Unsigned integer parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*Identity)[^)]*\)").unwrap(), // Identity parameters  
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*Address)[^)]*\)").unwrap(), // Address parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*AssetId)[^)]*\)").unwrap(), // Asset ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*ContractId)[^)]*\)").unwrap(), // Contract ID parameters
        Regex::new(r"fn\s+\w+\s*\([^)]*(\w+:\s*b256)[^)]*\)").unwrap(), // Hash parameters
    ]
});

// More comprehensive validation patterns
static VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*\w+\s*[><!]=?\s*\d+").unwrap(), // Boundary checks
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Address::zero\(\)").unwrap(), // Zero address checks
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Identity::Address\(Address::zero\(\)\)").unwrap(), // Identity zero checks
        Regex::new(r"require\s*\(\s*\w+\s*>\s*0").unwrap(), // Non-zero checks
        Regex::new(r"assert\s*\(\s*\w+").unwrap(), // Assert statements
        Regex::new(r"revert\s*\(").unwrap(), // Explicit reverts
        Regex::new(r"(?i)validate|check|verify").unwrap(), // Validation functions
        Regex::new(r"if\s+\w+\s*[<>=!]+\s*\d+\s*\{[^}]*revert").unwrap(), // Conditional reverts
    ]
});

// High-risk operations requiring validation
static HIGH_RISK_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\([^)]*amount").unwrap(), // Asset transfers with amount
        Regex::new(r"mint_to\s*\([^)]*amount").unwrap(), // Minting with amount
        Regex::new(r"burn\s*\([^)]*amount").unwrap(), // Burning with amount
        Regex::new(r"storage\.\w+\.write\s*\(\s*\w+").unwrap(), // Storage writes
        Regex::new(r"force_transfer_to_contract").unwrap(), // Force transfers
        Regex::new(r"approve\s*\([^)]*amount").unwrap(), // Approvals with amount
    ]
});

// Financial context patterns that increase risk
static FINANCIAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)balance|amount|price|value|fund|asset|token").unwrap(),
        Regex::new(r"(?i)withdraw|deposit|mint|burn|transfer|liquidate").unwrap(),
        Regex::new(r"(?i)collateral|debt|loan|interest|fee").unwrap(),
    ]
});

// Safe function patterns that don't need validation
static SAFE_FUNCTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)view|pure|get|read|query|balance_of|total_supply").unwrap(),
        Regex::new(r"(?i)info|status|metadata|config").unwrap(),
        Regex::new(r"fn\s+test_").unwrap(), // Test functions
        Regex::new(r"#\[test\]").unwrap(), // Test annotations
    ]
});

// Function call patterns for FCG
static FUNCTION_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(\w+)\s*\([^)]*\)").unwrap(), // Basic function calls
        Regex::new(r"self\.(\w+)\s*\([^)]*\)").unwrap(), // Self function calls
        Regex::new(r"(\w+)\.(\w+)\s*\([^)]*\)").unwrap(), // External contract calls
    ]
});

// Strong validation patterns for PPL
static STRONG_VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*\w+\s*[><]=?\s*\d+\s*&&\s*\w+\s*[><]=?\s*\d+").unwrap(), // Multiple conditions
        Regex::new(r"require\s*\(\s*\w+\s*!=\s*Address::zero\(\)\s*&&\s*\w+\s*>\s*0").unwrap(), // Combined checks
        Regex::new(r"if\s*\(\s*\w+\s*[<>=!]+\s*\d+\s*\)\s*\{[^}]*require").unwrap(), // Nested validation
        Regex::new(r"(?i)validate_.*\(.*\)").unwrap(), // Custom validation functions
    ]
});

impl InputValidationDetector {
    pub fn new() -> Self {
        Self
    }

    // Function Call Graph (FCG) - maps callers and callees for input validation
    fn build_input_validation_fcg(&self, file: &SwayFile) -> InputValidationFCG {
        let mut fcg = InputValidationFCG {
            callers: HashMap::new(),
            callees: HashMap::new(),
            function_signatures: HashMap::new(),
        };

        let lines: Vec<&str> = file.content.lines().collect();
        let mut current_function: Option<String> = None;
        let mut function_start = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Detect function definitions
            if trimmed.starts_with("fn ") {
                if let Some(func_name) = self.extract_function_name(line) {
                    if let Some(current) = &current_function {
                        // Store previous function signature
                        let signature = InputValidationSignature {
                            name: current.clone(),
                            line_start: function_start,
                            line_end: line_num - 1,
                            parameters: self.extract_function_parameters(&lines, function_start),
                            parameter_types: self.extract_parameter_types(&lines, function_start),
                            has_validation: self.has_validation_in_function(&lines, function_start),
                            validation_context: self.extract_validation_context(&lines, function_start, line_num - 1),
                            risk_level: self.calculate_risk_level(&lines, function_start),
                            called_by_validated_functions: false,
                        };
                        fcg.function_signatures.insert(current.clone(), signature);
                    }

                    current_function = Some(func_name.clone());
                    function_start = line_num;
                    
                    // Initialize callers/callees for new function
                    fcg.callers.entry(func_name.clone()).or_insert_with(HashSet::new);
                    fcg.callees.entry(func_name.clone()).or_insert_with(HashSet::new);
                }
            }

            // Detect function calls within current function
            if let Some(current_func) = &current_function {
                let calls = self.extract_function_calls(line);
                for call in calls {
                    fcg.callers.entry(call.clone()).or_insert_with(HashSet::new).insert(current_func.clone());
                    fcg.callees.entry(current_func.clone()).or_insert_with(HashSet::new).insert(call);
                }
            }
        }

        // Store the last function
        if let Some(current) = &current_function {
            let signature = InputValidationSignature {
                name: current.clone(),
                line_start: function_start,
                line_end: lines.len(),
                parameters: self.extract_function_parameters(&lines, function_start),
                parameter_types: self.extract_parameter_types(&lines, function_start),
                has_validation: self.has_validation_in_function(&lines, function_start),
                validation_context: self.extract_validation_context(&lines, function_start, lines.len()),
                risk_level: self.calculate_risk_level(&lines, function_start),
                called_by_validated_functions: false,
            };
            fcg.function_signatures.insert(current.clone(), signature);
        }

        fcg
    }

    // Protection Propagation Layer (PPL) - propagates validation conditions
    fn build_input_validation_ppl(&self, fcg: &InputValidationFCG) -> InputValidationPPL {
        let mut ppl = InputValidationPPL {
            validated_functions: HashSet::new(),
            validation_sources: HashMap::new(),
            propagation_paths: HashMap::new(),
            validation_strength: HashMap::new(),
        };

        // Find functions with direct validation
        for (func_name, signature) in &fcg.function_signatures {
            if signature.has_validation {
                ppl.validated_functions.insert(func_name.clone());
                ppl.validation_sources.insert(func_name.clone(), vec![func_name.clone()]);
                
                // Determine validation strength
                let strength = self.determine_validation_strength(&signature.validation_context);
                ppl.validation_strength.insert(func_name.clone(), strength);
            }
        }

        // Propagate validation through call chains
        let mut queue: VecDeque<String> = ppl.validated_functions.iter().cloned().collect();
        let mut visited = HashSet::new();

        while let Some(current_func) = queue.pop_front() {
            if visited.contains(&current_func) {
                continue;
            }
            visited.insert(current_func.clone());

            // Propagate to callers (functions that call this validated function)
            if let Some(callers) = fcg.callers.get(&current_func) {
                for caller in callers {
                    if !ppl.validated_functions.contains(caller) {
                        ppl.validated_functions.insert(caller.clone());
                        
                        // Build propagation path
                        let mut path = ppl.propagation_paths.get(&current_func).unwrap_or(&vec![]).clone();
                        path.push(current_func.clone());
                        ppl.propagation_paths.insert(caller.clone(), path);
                        
                        // Inherit validation strength (but reduce it)
                        if let Some(strength) = ppl.validation_strength.get(&current_func) {
                            let inherited_strength = match strength {
                                ValidationStrength::Robust => ValidationStrength::Strong,
                                ValidationStrength::Strong => ValidationStrength::Medium,
                                ValidationStrength::Medium => ValidationStrength::Weak,
                                ValidationStrength::Weak => ValidationStrength::Weak,
                            };
                            ppl.validation_strength.insert(caller.clone(), inherited_strength);
                        }
                        
                        queue.push_back(caller.clone());
                    }
                }
            }
        }

        ppl
    }

    // Parameter Dependency Graph (PDG) - tracks how parameters and validation flow
    fn build_input_validation_pdg(&self, file: &SwayFile, fcg: &InputValidationFCG) -> InputValidationPDG {
        let mut pdg = InputValidationPDG {
            parameter_flows: HashMap::new(),
            validation_dependencies: HashMap::new(),
            risk_parameters: HashSet::new(),
            validation_coverage: HashMap::new(),
        };

        let lines: Vec<&str> = file.content.lines().collect();

        for (func_name, signature) in &fcg.function_signatures {
            let mut flows = Vec::new();
            let mut validations = Vec::new();
            let mut coverage: f64 = 0.0;

            // Analyze parameter flows within function
            for line_num in signature.line_start..signature.line_end {
                if line_num >= lines.len() {
                    break;
                }
                let line = lines[line_num];

                // Track parameter usage
                for param in &signature.parameters {
                    if line.contains(param) {
                        flows.push(format!("{} -> {}", param, line.trim()));
                    }
                }

                // Track validation patterns
                if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                    validations.push(line.trim().to_string());
                    coverage += 0.2; // Increment coverage for each validation
                }
            }

            pdg.parameter_flows.insert(func_name.clone(), flows);
            pdg.validation_dependencies.insert(func_name.clone(), validations);
            pdg.validation_coverage.insert(func_name.clone(), coverage.min(1.0));

            // Identify risk parameters
            for param in &signature.parameters {
                if self.is_risk_parameter(param, &signature.parameter_types) {
                    pdg.risk_parameters.insert(func_name.clone());
                }
            }
        }

        pdg
    }

    // Context Validity Checker (CVC) - final validator for input validation
    fn input_validation_cvc(&self, fcg: &InputValidationFCG, ppl: &InputValidationPPL, pdg: &InputValidationPDG) -> InputValidationCVC {
        let mut cvc = InputValidationCVC {
            valid_contexts: HashSet::new(),
            context_rules: HashMap::new(),
            validation_results: HashMap::new(),
            false_positive_filters: HashSet::new(),
        };

        for (func_name, signature) in &fcg.function_signatures {
            let mut is_valid = true;
            let mut rules = Vec::new();

            // Rule 1: Functions with risk parameters must have validation
            if !signature.parameters.is_empty() && signature.risk_level == RiskLevel::High {
                if !signature.has_validation && !ppl.validated_functions.contains(func_name) {
                    is_valid = false;
                    rules.push("High-risk function with parameters lacks validation".to_string());
                }
            }

            // Rule 2: Functions called by validated functions should be validated
            if let Some(callees) = fcg.callees.get(func_name) {
                for callee in callees {
                    if ppl.validated_functions.contains(callee) && !ppl.validated_functions.contains(func_name) {
                        is_valid = false;
                        rules.push(format!("Function called by validated function '{}' but not validated", callee));
                    }
                }
            }

            // Rule 3: Check validation coverage
            if let Some(coverage) = pdg.validation_coverage.get(func_name) {
                if *coverage < 0.3 && signature.risk_level == RiskLevel::Medium {
                    is_valid = false;
                    rules.push("Insufficient validation coverage for medium-risk function".to_string());
                }
            }

            // Rule 4: Filter out false positives
            if self.is_false_positive(func_name, signature, ppl) {
                cvc.false_positive_filters.insert(func_name.clone());
                is_valid = true; // Override to true for false positives
            }

            // Rule 5: Check for strong validation patterns
            if signature.risk_level == RiskLevel::Critical {
                if let Some(strength) = ppl.validation_strength.get(func_name) {
                    if *strength == ValidationStrength::Weak {
                        is_valid = false;
                        rules.push("Critical function has weak validation".to_string());
                    }
                }
            }

            cvc.validation_results.insert(func_name.clone(), is_valid);
            cvc.context_rules.insert(func_name.clone(), rules);

            if is_valid {
                cvc.valid_contexts.insert(func_name.clone());
            }
        }

        cvc
    }

    // Helper methods for FCG
    fn extract_function_name(&self, line: &str) -> Option<String> {
        let func_pattern = Regex::new(r"fn\s+(\w+)").unwrap();
        func_pattern.captures(line).map(|caps| caps[1].to_string())
    }

    fn extract_function_parameters(&self, lines: &[&str], start_line: usize) -> Vec<String> {
        if start_line >= lines.len() {
            return Vec::new();
        }
        let line = lines[start_line];
        let param_pattern = Regex::new(r"fn\s+\w+\s*\(([^)]*)\)").unwrap();
        param_pattern.captures(line)
            .map(|caps| {
                caps[1].split(',')
                    .map(|s| s.trim().split(':').next().unwrap_or("").trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or(Vec::new())
    }

    fn extract_parameter_types(&self, lines: &[&str], start_line: usize) -> HashMap<String, String> {
        let mut types = HashMap::new();
        if start_line >= lines.len() {
            return types;
        }
        let line = lines[start_line];
        let param_pattern = Regex::new(r"fn\s+\w+\s*\(([^)]*)\)").unwrap();
        if let Some(captures) = param_pattern.captures(line) {
            for param in captures[1].split(',') {
                let parts: Vec<&str> = param.trim().split(':').collect();
                if parts.len() == 2 {
                    types.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
                }
            }
        }
        types
    }

    fn has_validation_in_function(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn extract_validation_context(&self, lines: &[&str], start_line: usize, end_line: usize) -> Vec<String> {
        let mut context = Vec::new();
        for i in start_line..std::cmp::min(end_line, lines.len()) {
            let line = lines[i];
            if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                context.push(line.trim().to_string());
            }
        }
        context
    }

    fn calculate_risk_level(&self, lines: &[&str], start_line: usize) -> RiskLevel {
        let mut risk_score = 0;
        
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if HIGH_RISK_OPERATIONS.iter().any(|p| p.is_match(line)) {
                risk_score += 3;
            }
            
            if FINANCIAL_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 2;
            }
            
            if line.contains("storage.") && line.contains(".write") {
                risk_score += 2;
            }
        }
        
        match risk_score {
            0..=2 => RiskLevel::Low,
            3..=5 => RiskLevel::Medium,
            6..=8 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    fn extract_function_calls(&self, line: &str) -> Vec<String> {
        let mut calls = Vec::new();
        for pattern in FUNCTION_CALL_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(line) {
                if captures.len() > 1 {
                    calls.push(captures[1].to_string());
                }
            }
        }
        calls
    }

    // Helper methods for PPL
    fn determine_validation_strength(&self, validation_context: &[String]) -> ValidationStrength {
        let mut strength_score = 0;
        
        for validation in validation_context {
            if STRONG_VALIDATION_PATTERNS.iter().any(|p| p.is_match(validation)) {
                strength_score += 3;
            } else if VALIDATION_PATTERNS.iter().any(|p| p.is_match(validation)) {
                strength_score += 1;
            }
        }
        
        match strength_score {
            0 => ValidationStrength::Weak,
            1..=2 => ValidationStrength::Medium,
            3..=5 => ValidationStrength::Strong,
            _ => ValidationStrength::Robust,
        }
    }

    // Helper methods for PDG
    fn is_risk_parameter(&self, param: &str, types: &HashMap<String, String>) -> bool {
        if let Some(param_type) = types.get(param) {
            param_type.contains("u64") || param_type.contains("u32") || 
            param_type.contains("Address") || param_type.contains("Identity") ||
            param_type.contains("AssetId") || param_type.contains("ContractId")
        } else {
            false
        }
    }

    // Helper methods for CVC
    fn is_false_positive(&self, func_name: &str, signature: &InputValidationSignature, ppl: &InputValidationPPL) -> bool {
        // Filter out safe functions
        if SAFE_FUNCTION_PATTERNS.iter().any(|p| p.is_match(func_name)) {
            return true;
        }
        
        // Filter out functions with strong validation
        if ppl.validated_functions.contains(func_name) {
            if let Some(strength) = ppl.validation_strength.get(func_name) {
                if *strength == ValidationStrength::Strong || *strength == ValidationStrength::Robust {
                    return true;
                }
            }
        }
        
        // Filter out low-risk functions
        if signature.risk_level == RiskLevel::Low {
            return true;
        }
        
        false
    }

    // Enhanced analysis with advanced layers
    fn analyze_with_advanced_layers(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build Function Call Graph
        let fcg = self.build_input_validation_fcg(file);
        
        // Build Protection Propagation Layer
        let ppl = self.build_input_validation_ppl(&fcg);
        
        // Build Parameter Dependency Graph
        let pdg = self.build_input_validation_pdg(file, &fcg);
        
        // Run Context Validity Checker
        let cvc = self.input_validation_cvc(&fcg, &ppl, &pdg);

        // Generate findings based on advanced analysis
        for (func_name, is_valid) in &cvc.validation_results {
            if !is_valid && !cvc.false_positive_filters.contains(func_name) {
                if let Some(signature) = fcg.function_signatures.get(func_name) {
                    let empty_rules: Vec<String> = Vec::new();
                    let rules = cvc.context_rules.get(func_name).unwrap_or(&empty_rules);
                    
                    let severity = match signature.risk_level {
                        RiskLevel::Critical => Severity::Critical,
                        RiskLevel::High => Severity::High,
                        RiskLevel::Medium => Severity::Medium,
                        RiskLevel::Low => Severity::Low,
                    };

                    let confidence = if ppl.validated_functions.contains(func_name) {
                        0.6 // Lower confidence if function is validated
                    } else {
                        0.9 // High confidence for unvalidated functions
                    };

                    findings.push(
                        Finding::new(
                            self.name(),
                            severity,
                            Category::Security,
                            confidence,
                            "Advanced Input Validation Analysis",
                            &format!(
                                "Function '{}' failed advanced input validation validation. Issues: {}",
                                func_name,
                                rules.join(", ")
                            ),
                            &file.path,
                            signature.line_start,
                            0,
                            extract_code_snippet(&file.content, signature.line_start, 5),
                            "Implement comprehensive input validation mechanisms and ensure all parameters are properly validated through the call chain.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![20, 129, 190])
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn analyze_function_parameters(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;

            // Skip safe functions
            if SAFE_FUNCTION_PATTERNS.iter().any(|p| p.is_match(line)) {
                continue;
            }

            // Check for risky function parameters
            for pattern in RISKY_PARAMETER_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let has_validation = self.has_comprehensive_validation(&lines, line_num);
                    let has_risky_ops = self.has_high_risk_operations(&lines, line_num);
                    let is_financial_context = self.is_financial_function(&lines, line_num);
                    
                    // Only report if there are risky operations AND no validation
                    if !has_validation && (has_risky_ops || is_financial_context) {
                        let confidence = self.calculate_confidence(line, &lines, line_num, is_financial_context, has_risky_ops);
                        
                        // Only report high confidence findings to minimize false positives
                        if confidence >= 0.7 {
                            let severity = if is_financial_context && has_risky_ops {
                                Severity::High
                            } else if has_risky_ops {
                                Severity::Medium  
                            } else {
                                Severity::Low
                            };

                            findings.push(
                                Finding::new(
                                    self.name(),
                                    severity,
                                    Category::Security,
                                    confidence,
                                    "Insufficient Input Validation",
                                    &format!(
                                        "Function at line {} accepts parameters {} but performs dangerous operations without sufficient validation: {}. Risk factors: {}. Unvalidated inputs can lead to vulnerabilities.",
                                        line_num,
                                        captures.as_str(),
                                        self.get_risk_operations(&lines, line_num),
                                        self.get_risk_factors(is_financial_context, has_risky_ops)
                                    ),
                                    &file.path,
                                    line_num,
                                    captures.start(),
                                    extract_code_snippet(&file.content, line_num, 3),
                                    "Implement comprehensive input validation: (1) Add require() statements for parameter bounds, (2) Check for zero addresses/IDs, (3) Validate ranges before arithmetic operations, (4) Use checked arithmetic for financial calculations, (5) Add parameter sanitization for arrays/loops.",
                                )
                                .with_context(context.clone())
                                .with_cwe(vec![20, 129, 190]) // Improper Input Validation, Improper Validation of Array Index, Integer Overflow
                                .with_references(vec![
                                    Reference {
                                        title: "OWASP Input Validation Cheat Sheet".to_string(),
                                        url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html".to_string(),
                                        reference_type: ReferenceType::Security,
                                    },
                                ])
                                .with_effort(EstimatedEffort::Easy)
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn has_comprehensive_validation(&self, lines: &[&str], start_line: usize) -> bool {
        // Look for validation in the function (next 20 lines or until next function)
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            // Stop if we reach another function
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            // Check for comprehensive validation patterns
            if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn has_high_risk_operations(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 25, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if HIGH_RISK_OPERATIONS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn is_financial_function(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if FINANCIAL_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn calculate_confidence(&self, line: &str, lines: &[&str], line_num: usize, is_financial: bool, has_risky_ops: bool) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence
        
        // Higher confidence for financial functions
        if is_financial {
            confidence += 0.3;
        }
        
        // Higher confidence for risky operations
        if has_risky_ops {
            confidence += 0.3;
        }
        
        // Check for specific risky parameter types
        if line.contains("amount") || line.contains("value") {
            confidence += 0.2;
        }
        
        if line.contains("Address") || line.contains("Identity") {
            confidence += 0.15;
        }
        
        // Lower confidence if validation patterns are nearby but not recognized
        if self.has_nearby_validation_attempts(lines, line_num) {
            confidence -= 0.2;
        }
        
        confidence.min(1.0)
    }

    fn has_nearby_validation_attempts(&self, lines: &[&str], start_line: usize) -> bool {
        let start = if start_line > 3 { start_line - 3 } else { 0 };
        let end = std::cmp::min(start_line + 10, lines.len());
        
        for i in start..end {
            let line = lines[i];
            if line.contains("if ") && (line.contains("==") || line.contains("!=") || line.contains(">") || line.contains("<")) {
                return true;
            }
        }
        false
    }

    fn get_risk_operations(&self, lines: &[&str], start_line: usize) -> String {
        let mut operations = Vec::new();
        
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if line.contains("transfer") { operations.push("transfer"); }
            if line.contains("mint") { operations.push("mint"); }
            if line.contains("burn") { operations.push("burn"); }
            if line.contains("storage.") && line.contains(".write") { operations.push("storage write"); }
            if line.contains("approve") { operations.push("approve"); }
        }
        
        if operations.is_empty() {
            "dangerous operations".to_string()
        } else {
            operations.join(", ")
        }
    }

    fn get_risk_factors(&self, is_financial: bool, has_risky_ops: bool) -> String {
        let mut factors = Vec::new();
        
        if is_financial {
            factors.push("Financial operation context");
        }
        
        if has_risky_ops {
            factors.push("High-risk operations present");
        }
        
        factors.push("Missing input bounds validation");
        factors.push("Missing overflow protection");
        
        factors.join(", ")
    }
}

impl Detector for InputValidationDetector {
    fn name(&self) -> &'static str {
        "input_validation"
    }
    
    fn description(&self) -> &'static str {
        "Detects insufficient input validation in functions with high-risk operations using advanced analysis layers (FCG, PPL, PDG, CVC)"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Enhanced analysis with advanced layers
        all_findings.extend(self.analyze_with_advanced_layers(file, context));
        
        // Traditional analysis for backward compatibility
        all_findings.extend(self.analyze_function_parameters(file, context));
        
        Ok(all_findings)
    }
} 