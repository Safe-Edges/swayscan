use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct LogicErrorDetector;

// Advanced Analysis Structures for Logic Errors
#[derive(Debug, Clone)]
struct LogicFCG {
    callers: HashMap<String, HashSet<String>>,
    callees: HashMap<String, HashSet<String>>,
    function_signatures: HashMap<String, LogicSignature>,
}

#[derive(Debug, Clone)]
struct LogicSignature {
    name: String,
    line_start: usize,
    line_end: usize,
    logic_operations: Vec<String>,
    has_validation: bool,
    validation_context: Vec<String>,
    risk_level: LogicRiskLevel,
    called_by_safe_functions: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum LogicRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct LogicPPL {
    safe_functions: HashSet<String>,
    safety_sources: HashMap<String, Vec<String>>,
    propagation_paths: HashMap<String, Vec<String>>,
    safety_strength: HashMap<String, SafetyStrength>,
}

#[derive(Debug, Clone, PartialEq)]
enum SafetyStrength {
    Weak,    // Basic checks
    Medium,  // Boundary checks
    Strong,  // Comprehensive validation
    Robust,  // Multiple validation layers
}

#[derive(Debug, Clone)]
struct LogicPDG {
    logic_flows: HashMap<String, Vec<String>>,
    validation_dependencies: HashMap<String, Vec<String>>,
    critical_logic: HashSet<String>,
    validation_coverage: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct LogicCVC {
    valid_contexts: HashSet<String>,
    context_rules: HashMap<String, Vec<String>>,
    validation_results: HashMap<String, bool>,
    false_positive_filters: HashSet<String>,
}

// Logic error patterns
static LOGIC_ERROR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"if\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Assignment in if condition
        Regex::new(r"while\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Assignment in while condition
        Regex::new(r"==\s*true\b").unwrap(), // Unnecessary comparison with true
        Regex::new(r"==\s*false\b").unwrap(), // Unnecessary comparison with false
        Regex::new(r"if\s*\(\s*!\s*\w+\s*==\s*false\s*\)").unwrap(), // Double negation
        Regex::new(r"if\s*\(\s*\w+\s*==\s*true\s*\)").unwrap(), // Redundant true comparison
    ]
});

// Off-by-one error patterns
static OFF_BY_ONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"for\s+\w+\s+in\s+0\.\.=?length").unwrap(), // Loop might go beyond bounds
        Regex::new(r"while\s+\w+\s*<=\s*\w*\.len\(\)").unwrap(), // While loop boundary issue
        Regex::new(r"\[\s*\w+\s*\+\s*1\s*\]").unwrap(), // Array access with +1 (potential overflow)
        Regex::new(r"\[\s*\w+\s*\-\s*1\s*\]").unwrap(), // Array access with -1 (potential underflow)
    ]
});

// Incorrect comparison patterns
static INCORRECT_COMPARISONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"if\s*\(\s*\w+\s*=\s*\w+\s*\)").unwrap(), // Single = instead of ==
        Regex::new(r">=\s*0\s*&&\s*\w+\s*<=\s*\w+").unwrap(), // Redundant >= 0 for unsigned
        Regex::new(r"u\d+.*>=\s*0").unwrap(), // Unsigned integer compared to 0
    ]
});

// State inconsistency patterns
static STATE_INCONSISTENCY: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.[\w\.]*\.write\([^)]*\);\s*storage\.[\w\.]*\.write\([^)]*\);").unwrap(), // Multiple storage writes without checks
        Regex::new(r"balance.*=.*amount.*transfer").unwrap(), // Balance update before transfer
        Regex::new(r"total.*supply.*\+=.*mint").unwrap(), // Supply update order
    ]
});

// Dead code patterns
static DEAD_CODE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"return\s*[^;]*;\s*\w+").unwrap(), // Code after return
        Regex::new(r"revert\s*[^;]*;\s*\w+").unwrap(), // Code after revert
        Regex::new(r"panic\s*[^;]*;\s*\w+").unwrap(), // Code after panic
        Regex::new(r"if\s*\(\s*true\s*\)\s*\{[^}]*\}\s*else\s*\{").unwrap(), // Unreachable else
        Regex::new(r"if\s*\(\s*false\s*\)\s*\{").unwrap(), // Unreachable if block
    ]
});

// Incorrect order patterns
static INCORRECT_ORDER: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer.*require").unwrap(), // Transfer before validation
        Regex::new(r"mint.*require").unwrap(), // Mint before validation
        Regex::new(r"storage\.[\w\.]*\.write.*require").unwrap(), // State change before validation
    ]
});

// Validation patterns
static VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(").unwrap(),
        Regex::new(r"assert\s*\(").unwrap(),
        Regex::new(r"if\s*let\s*").unwrap(),
        Regex::new(r"match\s*").unwrap(),
        Regex::new(r"unwrap_or\(").unwrap(),
        Regex::new(r"expect\(").unwrap(),
    ]
});

// Strong validation patterns
static STRONG_VALIDATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*[^)]*\.len\s*>\s*0").unwrap(), // Length validation
        Regex::new(r"require\s*\(\s*[^)]*\.is_some\s*\)").unwrap(), // Option validation
        Regex::new(r"require\s*\(\s*[^)]*\.is_ok\s*\)").unwrap(), // Result validation
        Regex::new(r"if\s*let\s*Some\s*\(\s*[^)]*\)\s*=\s*[^)]*").unwrap(), // Pattern matching
        Regex::new(r"match\s*[^{]*\{[^}]*=>\s*[^}]*,").unwrap(), // Comprehensive matching
    ]
});

// Critical logic patterns
static CRITICAL_LOGIC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\(").unwrap(), // Transfer operations
        Regex::new(r"mint\s*\(").unwrap(), // Mint operations
        Regex::new(r"burn\s*\(").unwrap(), // Burn operations
        Regex::new(r"storage\.[\w\.]*\.write\s*\(").unwrap(), // Storage writes
        Regex::new(r"abi\s*\(").unwrap(), // External calls
        Regex::new(r"contract_call\s*\(").unwrap(), // Contract calls
    ]
});

// Safe function patterns
static SAFE_FUNCTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)view|pure|get|read|query").unwrap(),
        Regex::new(r"fn\s+test_").unwrap(), // Test functions
        Regex::new(r"#\[test\]").unwrap(), // Test annotations
        Regex::new(r"fn\s+init").unwrap(), // Initialization functions
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

impl LogicErrorDetector {
    pub fn new() -> Self {
        Self
    }

    // Function Call Graph (FCG) - maps callers and callees for logic operations
    fn build_logic_fcg(&self, file: &SwayFile) -> LogicFCG {
        let mut fcg = LogicFCG {
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
                        let signature = LogicSignature {
                            name: current.clone(),
                            line_start: function_start,
                            line_end: line_num - 1,
                            logic_operations: self.extract_logic_operations(&lines, function_start, line_num - 1),
                            has_validation: self.has_validation_in_function(&lines, function_start),
                            validation_context: self.extract_validation_context(&lines, function_start, line_num - 1),
                            risk_level: self.calculate_logic_risk_level(&lines, function_start),
                            called_by_safe_functions: false,
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
            let signature = LogicSignature {
                name: current.clone(),
                line_start: function_start,
                line_end: lines.len(),
                logic_operations: self.extract_logic_operations(&lines, function_start, lines.len()),
                has_validation: self.has_validation_in_function(&lines, function_start),
                validation_context: self.extract_validation_context(&lines, function_start, lines.len()),
                risk_level: self.calculate_logic_risk_level(&lines, function_start),
                called_by_safe_functions: false,
            };
            fcg.function_signatures.insert(current.clone(), signature);
        }

        fcg
    }

    // Protection Propagation Layer (PPL) - propagates safety conditions
    fn build_logic_ppl(&self, fcg: &LogicFCG) -> LogicPPL {
        let mut ppl = LogicPPL {
            safe_functions: HashSet::new(),
            safety_sources: HashMap::new(),
            propagation_paths: HashMap::new(),
            safety_strength: HashMap::new(),
        };

        // Find functions with direct validation
        for (func_name, signature) in &fcg.function_signatures {
            if signature.has_validation {
                ppl.safe_functions.insert(func_name.clone());
                ppl.safety_sources.insert(func_name.clone(), vec![func_name.clone()]);
                
                // Determine safety strength
                let strength = self.determine_safety_strength(&signature.validation_context);
                ppl.safety_strength.insert(func_name.clone(), strength);
            }
        }

        // Propagate safety through call chains
        let mut queue: VecDeque<String> = ppl.safe_functions.iter().cloned().collect();
        let mut visited = HashSet::new();

        while let Some(current_func) = queue.pop_front() {
            if visited.contains(&current_func) {
                continue;
            }
            visited.insert(current_func.clone());

            // Propagate to callers (functions that call this safe function)
            if let Some(callers) = fcg.callers.get(&current_func) {
                for caller in callers {
                    if !ppl.safe_functions.contains(caller) {
                        ppl.safe_functions.insert(caller.clone());
                        
                        // Build propagation path
                        let empty_path: Vec<String> = Vec::new();
                        let mut path = ppl.propagation_paths.get(&current_func).unwrap_or(&empty_path).clone();
                        path.push(current_func.clone());
                        ppl.propagation_paths.insert(caller.clone(), path);
                        
                        // Inherit safety strength (but reduce it)
                        if let Some(strength) = ppl.safety_strength.get(&current_func) {
                            let inherited_strength = match strength {
                                SafetyStrength::Robust => SafetyStrength::Strong,
                                SafetyStrength::Strong => SafetyStrength::Medium,
                                SafetyStrength::Medium => SafetyStrength::Weak,
                                SafetyStrength::Weak => SafetyStrength::Weak,
                            };
                            ppl.safety_strength.insert(caller.clone(), inherited_strength);
                        }
                        
                        queue.push_back(caller.clone());
                    }
                }
            }
        }

        ppl
    }

    // Parameter Dependency Graph (PDG) - tracks how logic operations and validation flow
    fn build_logic_pdg(&self, file: &SwayFile, fcg: &LogicFCG) -> LogicPDG {
        let mut pdg = LogicPDG {
            logic_flows: HashMap::new(),
            validation_dependencies: HashMap::new(),
            critical_logic: HashSet::new(),
            validation_coverage: HashMap::new(),
        };

        let lines: Vec<&str> = file.content.lines().collect();

        for (func_name, signature) in &fcg.function_signatures {
            let mut flows = Vec::new();
            let mut validations = Vec::new();
            let mut coverage: f64 = 0.0;

            // Analyze logic flows within function
            for line_num in signature.line_start..signature.line_end {
                if line_num >= lines.len() {
                    break;
                }
                let line = lines[line_num];

                // Track logic operations
                if LOGIC_ERROR_PATTERNS.iter().any(|p| p.is_match(line)) ||
                   OFF_BY_ONE_PATTERNS.iter().any(|p| p.is_match(line)) ||
                   INCORRECT_COMPARISONS.iter().any(|p| p.is_match(line)) {
                    flows.push(line.trim().to_string());
                }

                // Track validation patterns
                if VALIDATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                    validations.push(line.trim().to_string());
                    coverage += 0.25; // Increment coverage for each validation
                }
            }

            pdg.logic_flows.insert(func_name.clone(), flows);
            pdg.validation_dependencies.insert(func_name.clone(), validations);
            pdg.validation_coverage.insert(func_name.clone(), coverage.min(1.0));

            // Identify critical logic
            for operation in &signature.logic_operations {
                if CRITICAL_LOGIC_PATTERNS.iter().any(|p| p.is_match(operation)) {
                    pdg.critical_logic.insert(func_name.clone());
                }
            }
        }

        pdg
    }

    // Context Validity Checker (CVC) - final validator for logic safety
    fn logic_cvc(&self, fcg: &LogicFCG, ppl: &LogicPPL, pdg: &LogicPDG) -> LogicCVC {
        let mut cvc = LogicCVC {
            valid_contexts: HashSet::new(),
            context_rules: HashMap::new(),
            validation_results: HashMap::new(),
            false_positive_filters: HashSet::new(),
        };

        for (func_name, signature) in &fcg.function_signatures {
            let mut is_valid = true;
            let mut rules = Vec::new();

            // Rule 1: Functions with logic operations must have validation
            if !signature.logic_operations.is_empty() && signature.risk_level == LogicRiskLevel::High {
                if !signature.has_validation && !ppl.safe_functions.contains(func_name) {
                    is_valid = false;
                    rules.push("High-risk function with logic operations lacks validation".to_string());
                }
            }

            // Rule 2: Functions called by safe functions should be safe
            if let Some(callees) = fcg.callees.get(func_name) {
                for callee in callees {
                    if ppl.safe_functions.contains(callee) && !ppl.safe_functions.contains(func_name) {
                        is_valid = false;
                        rules.push(format!("Function called by safe function '{}' but not safe", callee));
                    }
                }
            }

            // Rule 3: Check validation coverage for critical logic
            if pdg.critical_logic.contains(func_name) {
                if let Some(coverage) = pdg.validation_coverage.get(func_name) {
                    if *coverage < 0.5 {
                        is_valid = false;
                        rules.push("Insufficient validation coverage for critical logic operations".to_string());
                    }
                }
            }

            // Rule 4: Filter out false positives
            if self.is_false_positive(func_name, signature, ppl) {
                cvc.false_positive_filters.insert(func_name.clone());
                is_valid = true; // Override to true for false positives
            }

            // Rule 5: Check for strong validation patterns
            if signature.risk_level == LogicRiskLevel::Critical {
                if let Some(strength) = ppl.safety_strength.get(func_name) {
                    if *strength == SafetyStrength::Weak {
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

    fn extract_logic_operations(&self, lines: &[&str], start_line: usize, end_line: usize) -> Vec<String> {
        let mut operations = Vec::new();
        for i in start_line..std::cmp::min(end_line, lines.len()) {
            let line = lines[i];
            if LOGIC_ERROR_PATTERNS.iter().any(|p| p.is_match(line)) ||
               OFF_BY_ONE_PATTERNS.iter().any(|p| p.is_match(line)) ||
               INCORRECT_COMPARISONS.iter().any(|p| p.is_match(line)) {
                operations.push(line.trim().to_string());
            }
        }
        operations
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

    fn calculate_logic_risk_level(&self, lines: &[&str], start_line: usize) -> LogicRiskLevel {
        let mut risk_score = 0;
        
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if LOGIC_ERROR_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 2;
            }
            
            if CRITICAL_LOGIC_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 3;
            }
            
            if OFF_BY_ONE_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 2;
            }
        }
        
        match risk_score {
            0..=2 => LogicRiskLevel::Low,
            3..=5 => LogicRiskLevel::Medium,
            6..=8 => LogicRiskLevel::High,
            _ => LogicRiskLevel::Critical,
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
    fn determine_safety_strength(&self, validation_context: &[String]) -> SafetyStrength {
        let mut strength_score = 0;
        
        for validation in validation_context {
            if STRONG_VALIDATION_PATTERNS.iter().any(|p| p.is_match(validation)) {
                strength_score += 3;
            } else if VALIDATION_PATTERNS.iter().any(|p| p.is_match(validation)) {
                strength_score += 1;
            }
        }
        
        match strength_score {
            0 => SafetyStrength::Weak,
            1..=2 => SafetyStrength::Medium,
            3..=5 => SafetyStrength::Strong,
            _ => SafetyStrength::Robust,
        }
    }

    // Helper methods for CVC
    fn is_false_positive(&self, func_name: &str, signature: &LogicSignature, ppl: &LogicPPL) -> bool {
        // Filter out safe functions
        if SAFE_FUNCTION_PATTERNS.iter().any(|p| p.is_match(func_name)) {
            return true;
        }
        
        // Filter out functions with strong validation
        if ppl.safe_functions.contains(func_name) {
            if let Some(strength) = ppl.safety_strength.get(func_name) {
                if *strength == SafetyStrength::Strong || *strength == SafetyStrength::Robust {
                    return true;
                }
            }
        }
        
        // Filter out low-risk functions
        if signature.risk_level == LogicRiskLevel::Low {
            return true;
        }
        
        false
    }

    // Enhanced analysis with advanced layers
    fn analyze_with_advanced_layers(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build Function Call Graph
        let fcg = self.build_logic_fcg(file);
        
        // Build Protection Propagation Layer
        let ppl = self.build_logic_ppl(&fcg);
        
        // Build Parameter Dependency Graph
        let pdg = self.build_logic_pdg(file, &fcg);
        
        // Run Context Validity Checker
        let cvc = self.logic_cvc(&fcg, &ppl, &pdg);

        // Generate findings based on advanced analysis
        for (func_name, is_valid) in &cvc.validation_results {
            if !is_valid && !cvc.false_positive_filters.contains(func_name) {
                if let Some(signature) = fcg.function_signatures.get(func_name) {
                    let empty_rules: Vec<String> = Vec::new();
                    let rules = cvc.context_rules.get(func_name).unwrap_or(&empty_rules);
                    
                    let severity = match signature.risk_level {
                        LogicRiskLevel::Critical => Severity::Critical,
                        LogicRiskLevel::High => Severity::High,
                        LogicRiskLevel::Medium => Severity::Medium,
                        LogicRiskLevel::Low => Severity::Low,
                    };

                    let confidence = if ppl.safe_functions.contains(func_name) {
                        0.6 // Lower confidence if function is safe
                    } else {
                        0.9 // High confidence for unsafe functions
                    };

                    findings.push(
                        Finding::new(
                            self.name(),
                            severity,
                            Category::Reliability,
                            confidence,
                            "Advanced Logic Error Analysis",
                            &format!(
                                "Function '{}' failed advanced logic validation. Issues: {}",
                                func_name,
                                rules.join(", ")
                            ),
                            &file.path,
                            signature.line_start,
                            0,
                            extract_code_snippet(&file.content, signature.line_start, 5),
                            "Implement comprehensive logic validation mechanisms and ensure all logic operations are properly validated through the call chain.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![754, 682, 561])
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn find_logic_errors(&self, content: &str) -> Vec<(usize, String, String)> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        // Check for various logic error patterns
        for (i, line) in lines.iter().enumerate() {
            // Assignment in conditions
            for pattern in LOGIC_ERROR_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "logic_error".to_string()));
                }
            }
            
            // Off-by-one errors
            for pattern in OFF_BY_ONE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "off_by_one".to_string()));
                }
            }
            
            // Incorrect comparisons
            for pattern in INCORRECT_COMPARISONS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "incorrect_comparison".to_string()));
                }
            }
            
            // State inconsistency
            for pattern in STATE_INCONSISTENCY.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "state_inconsistency".to_string()));
                }
            }
            
            // Dead code
            for pattern in DEAD_CODE_PATTERNS.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "dead_code".to_string()));
                }
            }
            
            // Incorrect order
            for pattern in INCORRECT_ORDER.iter() {
                if let Some(mat) = pattern.find(line) {
                    findings.push((i + 1, mat.as_str().to_string(), "incorrect_order".to_string()));
                }
            }
        }
        
        findings
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
        
        // Get function content
        let end = (start + 40).min(lines.len());
        lines[start..end].join("\n")
    }

    fn calculate_logic_risk(&self, _line: &str, error_type: &str, function_content: &str) -> f64 {
        let mut risk_score: f64 = 0.0;
        
        // Base risk varies by error type
        match error_type {
            "logic_error" => risk_score += 0.7, // High risk for logic errors
            "off_by_one" => risk_score += 0.6, // Medium-high risk
            "incorrect_comparison" => risk_score += 0.5, // Medium risk
            "state_inconsistency" => risk_score += 0.8, // High risk
            "dead_code" => risk_score += 0.3, // Lower risk but still issues
            "incorrect_order" => risk_score += 0.9, // Very high risk
            _ => risk_score += 0.4,
        }
        
        // Higher risk in financial functions
        if function_content.contains("transfer") || function_content.contains("mint") || 
           function_content.contains("burn") || function_content.contains("balance") {
            risk_score += 0.2;
        }
        
        // Higher risk for storage operations
        if function_content.contains("storage.") && function_content.contains(".write") {
            risk_score += 0.2;
        }
        
        // Higher risk for external calls
        if function_content.contains("abi(") || function_content.contains("contract_call") {
            risk_score += 0.15;
        }
        
        // Reduce risk if comprehensive validation exists
        let validation_count = [
            function_content.contains("require"),
            function_content.contains("assert"),
            function_content.contains("match"),
            function_content.contains("if let"),
        ].iter().filter(|&&x| x).count();
        
        if validation_count >= 3 {
            risk_score *= 0.7;
        } else if validation_count >= 2 {
            risk_score *= 0.8;
        }
        
        risk_score.min(1.0)
    }

    fn get_error_details(&self, error_type: &str) -> (&str, &str, &str) {
        match error_type {
            "logic_error" => (
                "Logic Error",
                "Logic errors can cause unexpected behavior and potential vulnerabilities",
                "Review conditional logic and fix assignment/comparison errors"
            ),
            "off_by_one" => (
                "Off-by-One Error",
                "Array bounds or loop iteration errors can cause panics or undefined behavior",
                "Check array bounds and loop conditions carefully"
            ),
            "incorrect_comparison" => (
                "Incorrect Comparison",
                "Wrong comparison operators can lead to logic flaws",
                "Use correct comparison operators (== vs = vs >=)"
            ),
            "state_inconsistency" => (
                "State Inconsistency",
                "Inconsistent state updates can break contract invariants",
                "Ensure atomic state updates and proper ordering"
            ),
            "dead_code" => (
                "Dead Code",
                "Unreachable code may indicate logic errors",
                "Remove dead code or fix logic to make it reachable"
            ),
            "incorrect_order" => (
                "Incorrect Operation Order",
                "Wrong order of operations can cause security vulnerabilities",
                "Follow checks-effects-interactions pattern"
            ),
            _ => (
                "Logic Error",
                "Logic error detected",
                "Review and fix the logic error"
            ),
        }
    }
}

impl Detector for LogicErrorDetector {
    fn name(&self) -> &'static str {
        "logic_errors"
    }
    
    fn description(&self) -> &'static str {
        "Detects logic errors including off-by-one errors, incorrect comparisons, and state inconsistencies using advanced analysis layers (FCG, PPL, PDG, CVC)"
    }
    
    fn category(&self) -> Category {
        Category::Reliability
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Enhanced analysis with advanced layers
        all_findings.extend(self.analyze_with_advanced_layers(file, context));
        
        // Traditional analysis for backward compatibility
        let logic_errors = self.find_logic_errors(&file.content);
        
        for (line_num, pattern, error_type) in logic_errors {
            let line = file.content.lines().nth(line_num - 1).unwrap_or("");
            let function_content = self.extract_function_context(&file.content, line_num);
            
            let confidence = self.calculate_logic_risk(line, &error_type, &function_content);
            
            if confidence >= 0.6 {
                let severity = if confidence >= 0.9 {
                    Severity::High
                } else if confidence >= 0.7 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let (title, impact, recommendation) = self.get_error_details(&error_type);

                let mut risk_factors = Vec::new();
                if function_content.contains("transfer") || function_content.contains("mint") {
                    risk_factors.push("Financial operation context");
                }
                if function_content.contains("storage.") && function_content.contains(".write") {
                    risk_factors.push("State modification");
                }
                if function_content.contains("abi(") || function_content.contains("contract_call") {
                    risk_factors.push("External call context");
                }

                let finding = Finding::new(
                    self.name(),
                    severity,
                    self.category(),
                    confidence,
                    title,
                    &format!(
                        "{} detected at line {}: '{}'. {}. Risk factors: {}.",
                        title,
                        line_num,
                        pattern.trim(),
                        impact,
                        if risk_factors.is_empty() { "None identified".to_string() } else { risk_factors.join(", ") }
                    ),
                    &file.path,
                    line_num,
                    1,
                    extract_code_snippet(&file.content, line_num, 2),
                    recommendation,
                )
                .with_impact(&format!("Medium - {} can cause unexpected behavior or vulnerabilities", title.to_lowercase()))
                .with_effort(EstimatedEffort::Easy)
                .with_cwe(vec![754, 682, 561]) // CWE-754: Improper Check for Unusual Conditions, CWE-682: Incorrect Calculation, CWE-561: Dead Code
                .with_references(vec![
                    Reference {
                        title: "Sway Best Practices".to_string(),
                        url: "https://docs.fuel.network/docs/sway/advanced/best-practices/".to_string(),
                        reference_type: ReferenceType::Documentation,
                    },
                    Reference {
                        title: "Common Programming Errors".to_string(),
                        url: "https://cwe.mitre.org/data/definitions/754.html".to_string(),
                        reference_type: ReferenceType::Standard,
                    }
                ])
                .with_context(context.clone());
                
                all_findings.push(finding);
            }
        }
        
        Ok(all_findings)
    }
} 