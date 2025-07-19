use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct AccessControlDetector;

// Advanced Analysis Structures
#[derive(Debug, Clone)]
struct FunctionCallGraph {
    callers: HashMap<String, HashSet<String>>,
    callees: HashMap<String, HashSet<String>>,
    function_signatures: HashMap<String, FunctionSignature>,
}

#[derive(Debug, Clone)]
struct FunctionSignature {
    name: String,
    line_start: usize,
    line_end: usize,
    is_public: bool,
    has_access_control: bool,
    privileged_operations: Vec<String>,
    parameters: Vec<String>,
    return_type: Option<String>,
}

#[derive(Debug, Clone)]
struct ProtectionPropagationLayer {
    protected_functions: HashSet<String>,
    protection_sources: HashMap<String, Vec<String>>,
    propagation_paths: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct ParameterDependencyGraph {
    parameter_flows: HashMap<String, Vec<String>>,
    condition_dependencies: HashMap<String, Vec<String>>,
    access_control_parameters: HashSet<String>,
}

#[derive(Debug, Clone)]
struct ContextValidityChecker {
    valid_contexts: HashSet<String>,
    context_rules: HashMap<String, Vec<String>>,
    validation_results: HashMap<String, bool>,
}

// Privileged operations that require access control
static PRIVILEGED_OPERATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"fn\s+(\w*admin\w*|\w*owner\w*|\w*mint\w*|\w*burn\w*|\w*pause\w*|\w*emergency\w*)").unwrap(),
        Regex::new(r"fn\s+\w+.*\{[^}]*storage\.\w+\.write").unwrap(), // Functions that write to storage
        Regex::new(r"transfer_to_address\s*\(").unwrap(), // Asset transfers
        Regex::new(r"force_transfer_to_contract\s*\(").unwrap(),
        Regex::new(r"mint_to\s*\(").unwrap(), // Minting operations
        Regex::new(r"burn\s*\(").unwrap(), // Burning operations
        Regex::new(r"selfdestruct\s*\(|destroy\s*\(").unwrap(), // Contract destruction
    ]
});

// Access control patterns (good)
static ACCESS_CONTROL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*msg\.sender\s*==").unwrap(),
        Regex::new(r"require\s*\(\s*sender\s*==").unwrap(),
        Regex::new(r"assert\s*\(\s*msg\.sender\s*==").unwrap(),
        Regex::new(r"only_owner|onlyOwner").unwrap(),
        Regex::new(r"only_admin|onlyAdmin").unwrap(),
        Regex::new(r"authorized|is_authorized").unwrap(),
        Regex::new(r"has_role|hasRole").unwrap(),
        Regex::new(r"check_permission|checkPermission").unwrap(),
    ]
});

// Public function patterns
static PUBLIC_FUNCTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"#\[storage\(.*write.*\)\]\s*pub\s+fn").unwrap(),
        Regex::new(r"pub\s+fn\s+\w+").unwrap(),
    ]
});

// Admin/Owner state variables
static ADMIN_STATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\s*\{[^}]*owner\s*:").unwrap(),
        Regex::new(r"storage\s*\{[^}]*admin\s*:").unwrap(),
        Regex::new(r"let\s+owner\s*=").unwrap(),
        Regex::new(r"let\s+admin\s*=").unwrap(),
    ]
});

// Role-based patterns
static ROLE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)role|permission|auth").unwrap(),
        Regex::new(r"mapping.*address.*bool").unwrap(), // Role mappings
        Regex::new(r"enum.*Role|struct.*Role").unwrap(),
    ]
});

// Function call patterns
static FUNCTION_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(\w+)\s*\([^)]*\)").unwrap(), // Basic function calls
        Regex::new(r"self\.(\w+)\s*\([^)]*\)").unwrap(), // Self function calls
        Regex::new(r"(\w+)\.(\w+)\s*\([^)]*\)").unwrap(), // External contract calls
    ]
});

// Parameter and condition patterns
static PARAMETER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"fn\s+\w+\s*\(([^)]*)\)").unwrap(), // Function parameters
        Regex::new(r"if\s*\(([^)]*)\)").unwrap(), // If conditions
        Regex::new(r"require\s*\(([^)]*)\)").unwrap(), // Require conditions
        Regex::new(r"assert\s*\(([^)]*)\)").unwrap(), // Assert conditions
    ]
});

impl AccessControlDetector {
    pub fn new() -> Self {
        Self
    }

    // Function Call Graph (FCG) - maps callers and callees
    fn build_function_call_graph(&self, file: &SwayFile) -> FunctionCallGraph {
        let mut fcg = FunctionCallGraph {
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
                        let signature = FunctionSignature {
                            name: current.clone(),
                            line_start: function_start,
                            line_end: line_num - 1,
                            is_public: self.is_public_function(&lines, function_start),
                            has_access_control: self.has_access_control_in_function(&lines, function_start),
                            privileged_operations: self.extract_privileged_operations(&lines, function_start, line_num - 1),
                            parameters: self.extract_function_parameters(&lines, function_start),
                            return_type: self.extract_return_type(&lines, function_start),
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
            let signature = FunctionSignature {
                name: current.clone(),
                line_start: function_start,
                line_end: lines.len(),
                is_public: self.is_public_function(&lines, function_start),
                has_access_control: self.has_access_control_in_function(&lines, function_start),
                privileged_operations: self.extract_privileged_operations(&lines, function_start, lines.len()),
                parameters: self.extract_function_parameters(&lines, function_start),
                return_type: self.extract_return_type(&lines, function_start),
            };
            fcg.function_signatures.insert(current.clone(), signature);
        }

        fcg
    }

    // Protection Propagation Layer (PPL) - propagates access control conditions
    fn build_protection_propagation_layer(&self, fcg: &FunctionCallGraph) -> ProtectionPropagationLayer {
        let mut ppl = ProtectionPropagationLayer {
            protected_functions: HashSet::new(),
            protection_sources: HashMap::new(),
            propagation_paths: HashMap::new(),
        };

        // Find functions with direct access control
        for (func_name, signature) in &fcg.function_signatures {
            if signature.has_access_control {
                ppl.protected_functions.insert(func_name.clone());
                ppl.protection_sources.insert(func_name.clone(), vec![func_name.clone()]);
            }
        }

        // Propagate protection through call chains
        let mut queue: VecDeque<String> = ppl.protected_functions.iter().cloned().collect();
        let mut visited = HashSet::new();

        while let Some(current_func) = queue.pop_front() {
            if visited.contains(&current_func) {
                continue;
            }
            visited.insert(current_func.clone());

            // Propagate to callers (functions that call this protected function)
            if let Some(callers) = fcg.callers.get(&current_func) {
                for caller in callers {
                    if !ppl.protected_functions.contains(caller) {
                        ppl.protected_functions.insert(caller.clone());
                        
                        // Build propagation path
                        let mut path = ppl.propagation_paths.get(&current_func).unwrap_or(&vec![]).clone();
                        path.push(current_func.clone());
                        ppl.propagation_paths.insert(caller.clone(), path);
                        
                        queue.push_back(caller.clone());
                    }
                }
            }
        }

        ppl
    }

    // Parameter Dependency Graph (PDG) - tracks how parameters and conditions flow
    fn build_parameter_dependency_graph(&self, file: &SwayFile, fcg: &FunctionCallGraph) -> ParameterDependencyGraph {
        let mut pdg = ParameterDependencyGraph {
            parameter_flows: HashMap::new(),
            condition_dependencies: HashMap::new(),
            access_control_parameters: HashSet::new(),
        };

        let lines: Vec<&str> = file.content.lines().collect();

        for (func_name, signature) in &fcg.function_signatures {
            let mut flows = Vec::new();
            let mut conditions = Vec::new();

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

                // Track access control conditions
                if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                    conditions.push(line.trim().to_string());
                    pdg.access_control_parameters.insert(func_name.clone());
                }
            }

            pdg.parameter_flows.insert(func_name.clone(), flows);
            pdg.condition_dependencies.insert(func_name.clone(), conditions);
        }

        pdg
    }

    // Context Validity Checker (CVC) - final validator
    fn context_validity_checker(&self, fcg: &FunctionCallGraph, ppl: &ProtectionPropagationLayer, pdg: &ParameterDependencyGraph) -> ContextValidityChecker {
        let mut cvc = ContextValidityChecker {
            valid_contexts: HashSet::new(),
            context_rules: HashMap::new(),
            validation_results: HashMap::new(),
        };

        for (func_name, signature) in &fcg.function_signatures {
            let mut is_valid = true;
            let mut rules = Vec::new();

            // Rule 1: Public functions with privileged operations must have access control
            if signature.is_public && !signature.privileged_operations.is_empty() {
                if !signature.has_access_control && !ppl.protected_functions.contains(func_name) {
                    is_valid = false;
                    rules.push("Public function with privileged operations lacks access control".to_string());
                }
            }

            // Rule 2: Functions called by protected functions should be protected
            if let Some(callees) = fcg.callees.get(func_name) {
                for callee in callees {
                    if ppl.protected_functions.contains(callee) && !ppl.protected_functions.contains(func_name) {
                        is_valid = false;
                        rules.push(format!("Function called by protected function '{}' but not protected", callee));
                    }
                }
            }

            // Rule 3: Access control parameters should be properly validated
            if pdg.access_control_parameters.contains(func_name) {
                if let Some(conditions) = pdg.condition_dependencies.get(func_name) {
                    let has_proper_validation = conditions.iter().any(|cond| {
                        cond.contains("msg.sender") || cond.contains("sender") || 
                        cond.contains("owner") || cond.contains("admin")
                    });
                    if !has_proper_validation {
                        is_valid = false;
                        rules.push("Access control conditions lack proper validation".to_string());
                    }
                }
            }

            // Rule 4: Check for circular dependencies in protection
            if ppl.protected_functions.contains(func_name) {
                if let Some(path) = ppl.propagation_paths.get(func_name) {
                    if path.len() > 10 { // Arbitrary limit to detect potential circular dependencies
                        is_valid = false;
                        rules.push("Potential circular dependency in access control".to_string());
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

    fn is_public_function(&self, lines: &[&str], start_line: usize) -> bool {
        if start_line >= lines.len() {
            return false;
        }
        let line = lines[start_line];
        PUBLIC_FUNCTION_PATTERNS.iter().any(|p| p.is_match(line))
    }

    fn extract_privileged_operations(&self, lines: &[&str], start_line: usize, end_line: usize) -> Vec<String> {
        let mut operations = Vec::new();
        for i in start_line..std::cmp::min(end_line, lines.len()) {
            let line = lines[i];
            for pattern in PRIVILEGED_OPERATIONS.iter() {
                if pattern.is_match(line) {
                    operations.push(line.trim().to_string());
                }
            }
        }
        operations
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

    fn extract_return_type(&self, lines: &[&str], start_line: usize) -> Option<String> {
        if start_line >= lines.len() {
            return None;
        }
        let line = lines[start_line];
        let return_pattern = Regex::new(r"\)\s*->\s*(\w+)").unwrap();
        return_pattern.captures(line).map(|caps| caps[1].to_string())
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

    // Enhanced analysis with advanced layers
    fn analyze_with_advanced_layers(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build Function Call Graph
        let fcg = self.build_function_call_graph(file);
        
        // Build Protection Propagation Layer
        let ppl = self.build_protection_propagation_layer(&fcg);
        
        // Build Parameter Dependency Graph
        let pdg = self.build_parameter_dependency_graph(file, &fcg);
        
        // Run Context Validity Checker
        let cvc = self.context_validity_checker(&fcg, &ppl, &pdg);

        // Generate findings based on advanced analysis
        for (func_name, is_valid) in &cvc.validation_results {
            if !is_valid {
                if let Some(signature) = fcg.function_signatures.get(func_name) {
                    let empty_rules: Vec<String> = Vec::new();
                    let rules = cvc.context_rules.get(func_name).unwrap_or(&empty_rules);
                    
                    let severity = if signature.privileged_operations.contains(&"mint".to_string()) || 
                                     signature.privileged_operations.contains(&"burn".to_string()) {
                        Severity::Critical
                    } else if signature.is_public {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let confidence = if ppl.protected_functions.contains(func_name) {
                        0.6 // Lower confidence if function is protected
                    } else {
                        0.9 // High confidence for unprotected functions
                    };

                    findings.push(
                        Finding::new(
                            self.name(),
                            severity,
                            Category::Security,
                            confidence,
                            "Advanced Access Control Analysis",
                            &format!(
                                "Function '{}' failed advanced access control validation. Issues: {}",
                                func_name,
                                rules.join(", ")
                            ),
                            &file.path,
                            signature.line_start,
                            0,
                            extract_code_snippet(&file.content, signature.line_start, 5),
                            "Implement proper access control mechanisms and ensure all privileged operations are properly protected through the call chain.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![284, 285, 862])
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn analyze_missing_access_control(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;

            // Check for privileged operations without access control
            for pattern in PRIVILEGED_OPERATIONS.iter() {
                if let Some(captures) = pattern.find(line) {
                    // Look for access control in the function
                    let has_access_control = self.has_access_control_in_function(&lines, line_num);
                    
                    if !has_access_control {
                        let confidence = if line.contains("mint") || line.contains("burn") || line.contains("admin") {
                            0.9 // High confidence for critical functions
                        } else if line.contains("transfer") {
                            0.8
                        } else {
                            0.7
                        };

                        let severity = if line.contains("mint") || line.contains("burn") || line.contains("destroy") {
                            Severity::Critical
                        } else if line.contains("transfer") || line.contains("admin") {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        findings.push(
                            Finding::new(
                                self.name(),
                                severity,
                                Category::Security,
                                confidence,
                                "Missing Access Control",
                                &format!(
                                    "Function '{}' performs privileged operations but lacks proper access control checks. Unauthorized users may be able to call this function.",
                                    captures.as_str()
                                ),
                                &file.path,
                                line_num,
                                captures.start(),
                                extract_code_snippet(&file.content, line_num, 3),
                                "Implement proper access control checks using require() statements to verify msg.sender authority, role-based access control (RBAC), or ownership patterns.",
                            )
                            .with_context(context.clone())
                            .with_cwe(vec![284, 285, 862]) // Improper Access Control, Improper Authorization, Missing Authorization
                            .with_references(vec![
                                Reference {
                                    title: "OWASP Access Control Cheat Sheet".to_string(),
                                    url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html".to_string(),
                                    reference_type: ReferenceType::Security,
                                },
                            ])
                            .with_effort(EstimatedEffort::Medium)
                        );
                    }
                }
            }

            // Check for public functions with storage writes but no access control
            for pattern in PUBLIC_FUNCTION_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    if line.contains("write") || self.function_has_storage_writes(&lines, line_num) {
                        let has_access_control = self.has_access_control_in_function(&lines, line_num);
                        
                        if !has_access_control && !self.is_safe_public_function(line) {
                            findings.push(
                                Finding::new(
                                    self.name(),
                                    Severity::High,
                                    Category::Security,
                                    0.8,
                                    "Public Function Without Access Control",
                                    &format!(
                                        "Public function '{}' modifies contract state but has no access control. This allows any user to modify critical contract data.",
                                        captures.as_str()
                                    ),
                                    &file.path,
                                    line_num,
                                    captures.start(),
                                    extract_code_snippet(&file.content, line_num, 3),
                                    "Add access control checks to restrict who can call state-modifying functions. Consider using onlyOwner, role-based permissions, or other authorization mechanisms.",
                                )
                                .with_context(context.clone())
                                .with_cwe(vec![284, 862])
                                .with_effort(EstimatedEffort::Easy)
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn analyze_weak_access_control(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for weak authorization patterns
            if line.contains("tx.origin") {
                findings.push(
                    Finding::new(
                        self.name(),
                        Severity::High,
                        Category::Security,
                        0.9,
                        "Use of tx.origin for Authorization",
                        "Using tx.origin for authorization is dangerous as it can be exploited in phishing attacks. An attacker can trick users into calling malicious contracts that then call your contract.",
                        &file.path,
                        line_num,
                        line.find("tx.origin").unwrap_or(0),
                        extract_code_snippet(&file.content, line_num, 2),
                        "Use msg.sender instead of tx.origin for authorization checks. msg.sender represents the immediate caller, while tx.origin represents the original external account.",
                    )
                    .with_context(context.clone())
                    .with_cwe(vec![284])
                    .with_effort(EstimatedEffort::Easy)
                );
            }

            // Check for hardcoded addresses in access control
            if line.contains("==") && (line.contains("0x") && line.len() > 20) {
                if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Medium,
                            Category::Security,
                            0.75,
                            "Hardcoded Address in Access Control",
                            "Access control uses hardcoded addresses, making the contract inflexible and potentially insecure if private keys are compromised.",
                            &file.path,
                            line_num,
                            0,
                            extract_code_snippet(&file.content, line_num, 2),
                            "Use configurable admin/owner addresses stored in contract storage that can be updated through secure governance mechanisms.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![798]) // Use of Hard-coded Credentials
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn has_access_control_in_function(&self, lines: &[&str], start_line: usize) -> bool {
        // Look for access control patterns in the function (next 20 lines or until next function)
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            // Stop if we reach another function
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            // Check for access control patterns
            if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn function_has_storage_writes(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if line.contains("storage.") && line.contains(".write") {
                return true;
            }
        }
        false
    }

    fn is_safe_public_function(&self, line: &str) -> bool {
        let safe_patterns = [
            "view", "pure", "get", "read", "query", "balance", "info"
        ];
        
        safe_patterns.iter().any(|pattern| line.to_lowercase().contains(pattern))
    }
}

impl Detector for AccessControlDetector {
    fn name(&self) -> &'static str {
        "access_control"
    }
    
    fn description(&self) -> &'static str {
        "Detects missing or weak access controls that could allow unauthorized access to critical functions using advanced analysis layers (FCG, PPL, PDG, CVC)"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Enhanced analysis with advanced layers
        all_findings.extend(self.analyze_with_advanced_layers(file, context));
        
        // Traditional analysis for backward compatibility
        all_findings.extend(self.analyze_missing_access_control(file, context));
        
        // Analyze for weak access control patterns
        all_findings.extend(self.analyze_weak_access_control(file, context));
        
        Ok(all_findings)
    }
} 