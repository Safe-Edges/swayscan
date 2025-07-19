use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct UnprotectedStorageDetector;

// Advanced Analysis Structures for Unprotected Storage
#[derive(Debug, Clone)]
struct StorageFCG {
    callers: HashMap<String, HashSet<String>>,
    callees: HashMap<String, HashSet<String>>,
    function_signatures: HashMap<String, StorageSignature>,
}

#[derive(Debug, Clone)]
struct StorageSignature {
    name: String,
    line_start: usize,
    line_end: usize,
    storage_operations: Vec<String>,
    has_access_control: bool,
    access_control_context: Vec<String>,
    risk_level: StorageRiskLevel,
    called_by_protected_functions: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum StorageRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct StoragePPL {
    protected_functions: HashSet<String>,
    protection_sources: HashMap<String, Vec<String>>,
    propagation_paths: HashMap<String, Vec<String>>,
    protection_strength: HashMap<String, ProtectionStrength>,
}

#[derive(Debug, Clone, PartialEq)]
enum ProtectionStrength {
    Weak,    // Basic checks
    Medium,  // Boundary checks
    Strong,  // Comprehensive protection
    Robust,  // Multiple protection layers
}

#[derive(Debug, Clone)]
struct StoragePDG {
    storage_flows: HashMap<String, Vec<String>>,
    protection_dependencies: HashMap<String, Vec<String>>,
    critical_storage: HashSet<String>,
    protection_coverage: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct StorageCVC {
    valid_contexts: HashSet<String>,
    context_rules: HashMap<String, Vec<String>>,
    validation_results: HashMap<String, bool>,
    false_positive_filters: HashSet<String>,
}

// Storage operation patterns
static STORAGE_OPERATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.\w+\.write\s*\(").unwrap(), // Storage writes
        Regex::new(r"storage\.\w+\.insert\s*\(").unwrap(), // Storage inserts
        Regex::new(r"storage\.\w+\.delete\s*\(").unwrap(), // Storage deletes
        Regex::new(r"storage\.\w+\.clear\s*\(").unwrap(), // Storage clears
        Regex::new(r"storage\.\w+\.set\s*\(").unwrap(), // Storage sets
    ]
});

// Access control patterns
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

// Strong protection patterns
static STRONG_PROTECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*msg\.sender\s*==\s*storage\.owner").unwrap(), // Owner check
        Regex::new(r"require\s*\(\s*storage\.admin\s*==\s*msg\.sender").unwrap(), // Admin check
        Regex::new(r"if\s*\(\s*msg\.sender\s*==\s*storage\.owner\s*\)\s*\{[^}]*require").unwrap(), // Nested protection
        Regex::new(r"(?i)only_owner|only_admin").unwrap(), // Custom modifiers
    ]
});

// Critical storage patterns
static CRITICAL_STORAGE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.balance").unwrap(), // Balance storage
        Regex::new(r"storage\.total_supply").unwrap(), // Total supply
        Regex::new(r"storage\.owner").unwrap(), // Owner storage
        Regex::new(r"storage\.admin").unwrap(), // Admin storage
        Regex::new(r"storage\.balances").unwrap(), // Balances mapping
        Regex::new(r"storage\.allowances").unwrap(), // Allowances mapping
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

impl UnprotectedStorageDetector {
    pub fn new() -> Self {
        Self
    }

    // Function Call Graph (FCG) - maps callers and callees for storage operations
    fn build_storage_fcg(&self, file: &SwayFile) -> StorageFCG {
        let mut fcg = StorageFCG {
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
                        let signature = StorageSignature {
                            name: current.clone(),
                            line_start: function_start,
                            line_end: line_num - 1,
                            storage_operations: self.extract_storage_operations(&lines, function_start, line_num - 1),
                            has_access_control: self.has_access_control_in_function(&lines, function_start),
                            access_control_context: self.extract_access_control_context(&lines, function_start, line_num - 1),
                            risk_level: self.calculate_storage_risk_level(&lines, function_start),
                            called_by_protected_functions: false,
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
            let signature = StorageSignature {
                name: current.clone(),
                line_start: function_start,
                line_end: lines.len(),
                storage_operations: self.extract_storage_operations(&lines, function_start, lines.len()),
                has_access_control: self.has_access_control_in_function(&lines, function_start),
                access_control_context: self.extract_access_control_context(&lines, function_start, lines.len()),
                risk_level: self.calculate_storage_risk_level(&lines, function_start),
                called_by_protected_functions: false,
            };
            fcg.function_signatures.insert(current.clone(), signature);
        }

        fcg
    }

    // Protection Propagation Layer (PPL) - propagates protection conditions
    fn build_storage_ppl(&self, fcg: &StorageFCG) -> StoragePPL {
        let mut ppl = StoragePPL {
            protected_functions: HashSet::new(),
            protection_sources: HashMap::new(),
            propagation_paths: HashMap::new(),
            protection_strength: HashMap::new(),
        };

        // Find functions with direct access control
        for (func_name, signature) in &fcg.function_signatures {
            if signature.has_access_control {
                ppl.protected_functions.insert(func_name.clone());
                ppl.protection_sources.insert(func_name.clone(), vec![func_name.clone()]);
                
                // Determine protection strength
                let strength = self.determine_protection_strength(&signature.access_control_context);
                ppl.protection_strength.insert(func_name.clone(), strength);
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
                        
                        // Inherit protection strength (but reduce it)
                        if let Some(strength) = ppl.protection_strength.get(&current_func) {
                            let inherited_strength = match strength {
                                ProtectionStrength::Robust => ProtectionStrength::Strong,
                                ProtectionStrength::Strong => ProtectionStrength::Medium,
                                ProtectionStrength::Medium => ProtectionStrength::Weak,
                                ProtectionStrength::Weak => ProtectionStrength::Weak,
                            };
                            ppl.protection_strength.insert(caller.clone(), inherited_strength);
                        }
                        
                        queue.push_back(caller.clone());
                    }
                }
            }
        }

        ppl
    }

    // Parameter Dependency Graph (PDG) - tracks how storage operations and protection flow
    fn build_storage_pdg(&self, file: &SwayFile, fcg: &StorageFCG) -> StoragePDG {
        let mut pdg = StoragePDG {
            storage_flows: HashMap::new(),
            protection_dependencies: HashMap::new(),
            critical_storage: HashSet::new(),
            protection_coverage: HashMap::new(),
        };

        let lines: Vec<&str> = file.content.lines().collect();

        for (func_name, signature) in &fcg.function_signatures {
            let mut flows = Vec::new();
            let mut protections = Vec::new();
            let mut coverage: f64 = 0.0;

            // Analyze storage flows within function
            for line_num in signature.line_start..signature.line_end {
                if line_num >= lines.len() {
                    break;
                }
                let line = lines[line_num];

                // Track storage operations
                if STORAGE_OPERATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                    flows.push(line.trim().to_string());
                }

                // Track protection patterns
                if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                    protections.push(line.trim().to_string());
                    coverage += 0.3; // Increment coverage for each protection
                }
            }

            pdg.storage_flows.insert(func_name.clone(), flows);
            pdg.protection_dependencies.insert(func_name.clone(), protections);
            pdg.protection_coverage.insert(func_name.clone(), coverage.min(1.0));

            // Identify critical storage
            for operation in &signature.storage_operations {
                if CRITICAL_STORAGE_PATTERNS.iter().any(|p| p.is_match(operation)) {
                    pdg.critical_storage.insert(func_name.clone());
                }
            }
        }

        pdg
    }

    // Context Validity Checker (CVC) - final validator for storage protection
    fn storage_cvc(&self, fcg: &StorageFCG, ppl: &StoragePPL, pdg: &StoragePDG) -> StorageCVC {
        let mut cvc = StorageCVC {
            valid_contexts: HashSet::new(),
            context_rules: HashMap::new(),
            validation_results: HashMap::new(),
            false_positive_filters: HashSet::new(),
        };

        for (func_name, signature) in &fcg.function_signatures {
            let mut is_valid = true;
            let mut rules = Vec::new();

            // Rule 1: Functions with storage operations must have access control
            if !signature.storage_operations.is_empty() && signature.risk_level == StorageRiskLevel::High {
                if !signature.has_access_control && !ppl.protected_functions.contains(func_name) {
                    is_valid = false;
                    rules.push("High-risk function with storage operations lacks access control".to_string());
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

            // Rule 3: Check protection coverage for critical storage
            if pdg.critical_storage.contains(func_name) {
                if let Some(coverage) = pdg.protection_coverage.get(func_name) {
                    if *coverage < 0.5 {
                        is_valid = false;
                        rules.push("Insufficient protection coverage for critical storage operations".to_string());
                    }
                }
            }

            // Rule 4: Filter out false positives
            if self.is_false_positive(func_name, signature, ppl) {
                cvc.false_positive_filters.insert(func_name.clone());
                is_valid = true; // Override to true for false positives
            }

            // Rule 5: Check for strong protection patterns
            if signature.risk_level == StorageRiskLevel::Critical {
                if let Some(strength) = ppl.protection_strength.get(func_name) {
                    if *strength == ProtectionStrength::Weak {
                        is_valid = false;
                        rules.push("Critical function has weak protection".to_string());
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

    fn extract_storage_operations(&self, lines: &[&str], start_line: usize, end_line: usize) -> Vec<String> {
        let mut operations = Vec::new();
        for i in start_line..std::cmp::min(end_line, lines.len()) {
            let line = lines[i];
            if STORAGE_OPERATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                operations.push(line.trim().to_string());
            }
        }
        operations
    }

    fn has_access_control_in_function(&self, lines: &[&str], start_line: usize) -> bool {
        for i in start_line..std::cmp::min(start_line + 20, lines.len()) {
            let line = lines[i];
            
            if i > start_line && line.trim_start().starts_with("fn ") {
                break;
            }
            
            if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                return true;
            }
        }
        false
    }

    fn extract_access_control_context(&self, lines: &[&str], start_line: usize, end_line: usize) -> Vec<String> {
        let mut context = Vec::new();
        for i in start_line..std::cmp::min(end_line, lines.len()) {
            let line = lines[i];
            if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(line)) {
                context.push(line.trim().to_string());
            }
        }
        context
    }

    fn calculate_storage_risk_level(&self, lines: &[&str], start_line: usize) -> StorageRiskLevel {
        let mut risk_score = 0;
        
        for i in start_line..std::cmp::min(start_line + 15, lines.len()) {
            let line = lines[i];
            
            if STORAGE_OPERATION_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 2;
            }
            
            if CRITICAL_STORAGE_PATTERNS.iter().any(|p| p.is_match(line)) {
                risk_score += 3;
            }
            
            if line.contains("storage.") && line.contains(".write") {
                risk_score += 2;
            }
        }
        
        match risk_score {
            0..=2 => StorageRiskLevel::Low,
            3..=5 => StorageRiskLevel::Medium,
            6..=8 => StorageRiskLevel::High,
            _ => StorageRiskLevel::Critical,
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
    fn determine_protection_strength(&self, access_control_context: &[String]) -> ProtectionStrength {
        let mut strength_score = 0;
        
        for protection in access_control_context {
            if STRONG_PROTECTION_PATTERNS.iter().any(|p| p.is_match(protection)) {
                strength_score += 3;
            } else if ACCESS_CONTROL_PATTERNS.iter().any(|p| p.is_match(protection)) {
                strength_score += 1;
            }
        }
        
        match strength_score {
            0 => ProtectionStrength::Weak,
            1..=2 => ProtectionStrength::Medium,
            3..=5 => ProtectionStrength::Strong,
            _ => ProtectionStrength::Robust,
        }
    }

    // Helper methods for CVC
    fn is_false_positive(&self, func_name: &str, signature: &StorageSignature, ppl: &StoragePPL) -> bool {
        // Filter out safe functions
        if SAFE_FUNCTION_PATTERNS.iter().any(|p| p.is_match(func_name)) {
            return true;
        }
        
        // Filter out functions with strong protection
        if ppl.protected_functions.contains(func_name) {
            if let Some(strength) = ppl.protection_strength.get(func_name) {
                if *strength == ProtectionStrength::Strong || *strength == ProtectionStrength::Robust {
                    return true;
                }
            }
        }
        
        // Filter out low-risk functions
        if signature.risk_level == StorageRiskLevel::Low {
            return true;
        }
        
        false
    }

    // Enhanced analysis with advanced layers
    fn analyze_with_advanced_layers(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Build Function Call Graph
        let fcg = self.build_storage_fcg(file);
        
        // Build Protection Propagation Layer
        let ppl = self.build_storage_ppl(&fcg);
        
        // Build Parameter Dependency Graph
        let pdg = self.build_storage_pdg(file, &fcg);
        
        // Run Context Validity Checker
        let cvc = self.storage_cvc(&fcg, &ppl, &pdg);

        // Generate findings based on advanced analysis
        for (func_name, is_valid) in &cvc.validation_results {
            if !is_valid && !cvc.false_positive_filters.contains(func_name) {
                if let Some(signature) = fcg.function_signatures.get(func_name) {
                    let empty_rules: Vec<String> = Vec::new();
                    let rules = cvc.context_rules.get(func_name).unwrap_or(&empty_rules);
                    
                    let severity = match signature.risk_level {
                        StorageRiskLevel::Critical => Severity::Critical,
                        StorageRiskLevel::High => Severity::High,
                        StorageRiskLevel::Medium => Severity::Medium,
                        StorageRiskLevel::Low => Severity::Low,
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
                            "Advanced Storage Protection Analysis",
                            &format!(
                                "Function '{}' failed advanced storage protection validation. Issues: {}",
                                func_name,
                                rules.join(", ")
                            ),
                            &file.path,
                            signature.line_start,
                            0,
                            extract_code_snippet(&file.content, signature.line_start, 5),
                            "Implement comprehensive storage protection mechanisms and ensure all storage operations are properly protected through the call chain.",
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
}

impl Detector for UnprotectedStorageDetector {
    fn name(&self) -> &'static str {
        "unprotected_storage_variable"
    }
    
    fn description(&self) -> &'static str {
        "Finds storage modifications without access restrictions using advanced analysis layers (FCG, PPL, PDG, CVC)"
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
        for (line_num, line) in file.content.lines().enumerate() {
            if line.contains("storage.") && line.contains(".write(") {
                if !line.contains("require") && !line.contains("assert") && !line.contains("only_owner") {
                    let finding = Finding::new(
                        self.name(),
                        self.default_severity(),
                        self.category(),
                        0.8,
                        "Unprotected Storage Modification",
                        "Storage variable is modified without proper access control",
                        &file.path,
                        line_num + 1,
                        1,
                        extract_code_snippet(&file.content, line_num + 1, 2),
                        "Add access control checks before modifying storage variables",
                    )
                    .with_context(context.clone())
                    .with_cwe(vec![284, 285, 862])
                    .with_references(vec![
                        Reference {
                            title: "Smart Contract Security Best Practices".to_string(),
                            url: "https://consensys.net/blog/developers/smart-contract-security-best-practices/".to_string(),
                            reference_type: ReferenceType::Security,
                        },
                    ])
                    .with_effort(EstimatedEffort::Easy);
                    
                    all_findings.push(finding);
                }
            }
        }
        
        Ok(all_findings)
    }
}