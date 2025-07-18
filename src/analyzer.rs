use crate::parser::SwayFile;
use crate::detectors::AnalysisContext;
use std::collections::{HashMap, HashSet};
use regex::Regex;
use once_cell::sync::Lazy;

static FUNCTION_CALL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Direct function calls
        Regex::new(r"(\w+)\s*\(").unwrap(),
        // Method calls  
        Regex::new(r"\.(\w+)\s*\(").unwrap(),
        // Storage calls
        Regex::new(r"storage\.(\w+)\.(\w+)\s*\(").unwrap(),
    ]
});

static ACCESS_CONTROL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Direct require statements
        Regex::new(r"require\s*\(\s*([^)]+)\s*,\s*[^)]*\)").unwrap(),
        // Assert statements
        Regex::new(r"assert\s*\(\s*([^)]+)\s*\)").unwrap(),
        // Owner checks
        Regex::new(r"msg_sender\(\)\s*==\s*storage\.(\w+)").unwrap(),
        // Role checks
        Regex::new(r"has_role\s*\(\s*([^,)]+)").unwrap(),
        // Custom access control functions
        Regex::new(r"only_(\w+)\s*\(\s*\)").unwrap(),
    ]
});

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub line_start: usize,
    pub line_end: usize,
    pub parameters: Vec<String>,
    pub calls: Vec<String>,
    pub access_controls: Vec<AccessControl>,
    pub is_public: bool,
    pub has_storage_write: bool,
    pub has_external_calls: bool,
}

#[derive(Debug, Clone)]
pub struct AccessControl {
    pub condition: String,
    pub line: usize,
    pub protection_type: ProtectionType,
}

#[derive(Debug, Clone)]
pub enum ProtectionType {
    OwnerCheck,
    RoleCheck,
    ParameterValidation,
    StateValidation,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct FunctionCallGraph {
    pub functions: HashMap<String, FunctionInfo>,
    pub call_relationships: HashMap<String, Vec<String>>, // caller -> callees
    pub reverse_calls: HashMap<String, Vec<String>>,      // callee -> callers
    pub protection_propagation: HashMap<String, Vec<AccessControl>>, // function -> inherited protections
}

#[derive(Debug, Clone)]
pub struct ParameterFlow {
    pub parameter: String,
    pub source_function: String,
    pub target_function: String,
    pub validation_context: Vec<String>,
}

pub struct AdvancedAnalyzer {
    pub fcg: FunctionCallGraph,
    pub parameter_flows: Vec<ParameterFlow>,
}

impl AdvancedAnalyzer {
    pub fn new() -> Self {
        Self {
            fcg: FunctionCallGraph {
                functions: HashMap::new(),
                call_relationships: HashMap::new(),
                reverse_calls: HashMap::new(),
                protection_propagation: HashMap::new(),
            },
            parameter_flows: Vec::new(),
        }
    }

    pub fn analyze_context(&self, _file: &SwayFile) -> AnalysisContext {
        // Legacy method - keeping for compatibility
        AnalysisContext {
            function_name: None,
            contract_type: None,
            dependencies: Vec::new(),
            complexity_score: None,
            call_depth: None,
            variables_in_scope: Vec::new(),
        }
    }

    pub fn build_comprehensive_analysis(&mut self, file: &SwayFile) -> AnalysisContext {
        // Step 1: Extract all functions and their metadata
        self.extract_functions(file);
        
        // Step 2: Build call relationships
        self.build_call_graph(file);
        
        // Step 3: Propagate access control protections
        self.propagate_protections();
        
        // Step 4: Build parameter dependency graph
        self.build_parameter_flows(file);
        
        // Step 5: Return enriched context
        AnalysisContext {
            function_name: None,
            contract_type: Some("analyzed".to_string()),
            dependencies: Vec::new(),
            complexity_score: Some(self.fcg.functions.len() as u32),
            call_depth: Some(self.calculate_max_call_depth()),
            variables_in_scope: Vec::new(),
        }
    }

    fn extract_functions(&mut self, file: &SwayFile) {
        let lines: Vec<&str> = file.content.lines().collect();
        let mut current_function: Option<String> = None;
        let mut function_start = 0;
        let mut brace_depth = 0;
        
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Detect function start
            if let Some(func_name) = self.extract_function_name(trimmed) {
                current_function = Some(func_name.clone());
                function_start = line_num + 1;
                brace_depth = 0;
                
                // Initialize function info
                self.fcg.functions.insert(func_name.clone(), FunctionInfo {
                    name: func_name,
                    line_start: function_start,
                    line_end: 0,
                    parameters: self.extract_parameters(trimmed),
                    calls: Vec::new(),
                    access_controls: Vec::new(),
                    is_public: trimmed.contains("pub fn") || !trimmed.contains("fn "),
                    has_storage_write: trimmed.contains("storage(write)") || trimmed.contains("storage(read, write)"),
                    has_external_calls: false,
                });
            }
            
            // Track brace depth
            brace_depth += line.matches('{').count() as i32;
            brace_depth -= line.matches('}').count() as i32;
            
            // Extract access controls within function
            if let Some(ref func_name) = current_function {
                if let Some(access_control) = self.extract_access_control(line, line_num + 1) {
                    if let Some(func_info) = self.fcg.functions.get_mut(func_name) {
                        func_info.access_controls.push(access_control);
                    }
                }
                
                // Extract function calls
                let calls = self.extract_function_calls(line);
                if let Some(func_info) = self.fcg.functions.get_mut(func_name) {
                    func_info.calls.extend(calls);
                    
                    // Check for external calls
                    if line.contains("transfer(") || line.contains("mint(") || line.contains("burn(") {
                        func_info.has_external_calls = true;
                    }
                }
            }
            
            // Function end detection
            if brace_depth <= 0 && current_function.is_some() && line_num > function_start {
                if let Some(func_name) = current_function.take() {
                    if let Some(func_info) = self.fcg.functions.get_mut(&func_name) {
                        func_info.line_end = line_num + 1;
                    }
                }
            }
        }
    }

    fn extract_function_name(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find("fn ") {
            let after_fn = &line[start + 3..];
            if let Some(end) = after_fn.find('(') {
                return Some(after_fn[..end].trim().to_string());
            }
        }
        None
    }

    fn extract_parameters(&self, line: &str) -> Vec<String> {
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let params_str = &line[start + 1..end];
                return params_str
                    .split(',')
                    .map(|p| {
                        // Extract parameter name (before :)
                        if let Some(colon_pos) = p.find(':') {
                            p[..colon_pos].trim().to_string()
                        } else {
                            p.trim().to_string()
                        }
                    })
                    .filter(|p| !p.is_empty())
                    .collect();
            }
        }
        Vec::new()
    }

    fn extract_access_control(&self, line: &str, line_num: usize) -> Option<AccessControl> {
        for pattern in ACCESS_CONTROL_PATTERNS.iter() {
            if let Some(captures) = pattern.captures(line) {
                if let Some(condition) = captures.get(1) {
                    let protection_type = self.classify_protection(line);
                    return Some(AccessControl {
                        condition: condition.as_str().to_string(),
                        line: line_num,
                        protection_type,
                    });
                }
            }
        }
        None
    }

    fn classify_protection(&self, line: &str) -> ProtectionType {
        if line.contains("msg_sender") && line.contains("owner") {
            ProtectionType::OwnerCheck
        } else if line.contains("has_role") || line.contains("is_admin") {
            ProtectionType::RoleCheck
        } else if line.contains("amount") || line.contains("value") || line.contains("> 0") {
            ProtectionType::ParameterValidation
        } else if line.contains("storage.") {
            ProtectionType::StateValidation
        } else {
            ProtectionType::Custom(line.trim().to_string())
        }
    }

    fn extract_function_calls(&self, line: &str) -> Vec<String> {
        let mut calls = Vec::new();
        
        for pattern in FUNCTION_CALL_PATTERNS.iter() {
            for captures in pattern.captures_iter(line) {
                if let Some(func_name) = captures.get(1) {
                    let name = func_name.as_str().to_string();
                    // Filter out obvious non-function calls
                    if !["if", "while", "for", "match", "let", "return"].contains(&name.as_str()) {
                        calls.push(name);
                    }
                }
            }
        }
        
        calls
    }

    fn build_call_graph(&mut self, _file: &SwayFile) {
        // Build bidirectional call relationships
        for (caller, func_info) in &self.fcg.functions {
            let callees = func_info.calls.clone();
            self.fcg.call_relationships.insert(caller.clone(), callees.clone());
            
            // Build reverse mapping
            for callee in callees {
                self.fcg.reverse_calls
                    .entry(callee)
                    .or_insert_with(Vec::new)
                    .push(caller.clone());
            }
        }
    }

    fn propagate_protections(&mut self) {
        // Step 1: Start with functions that have direct access controls
        let mut protected_functions = HashSet::new();
        
        for (func_name, func_info) in &self.fcg.functions {
            if !func_info.access_controls.is_empty() {
                protected_functions.insert(func_name.clone());
                self.fcg.protection_propagation.insert(
                    func_name.clone(), 
                    func_info.access_controls.clone()
                );
            }
        }
        
        // Step 2: Propagate protections to callees (top-down)
        let mut changed = true;
        while changed {
            changed = false;
            
            for (caller, callees) in &self.fcg.call_relationships.clone() {
                if let Some(caller_protections) = self.fcg.protection_propagation.get(caller).cloned() {
                    for callee in callees {
                        if !protected_functions.contains(callee) {
                            // Only propagate to private functions or functions without their own protections
                            if let Some(callee_info) = self.fcg.functions.get(callee) {
                                if !callee_info.is_public && callee_info.access_controls.is_empty() {
                                    self.fcg.protection_propagation.insert(
                                        callee.clone(),
                                        caller_protections.clone()
                                    );
                                    protected_functions.insert(callee.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn build_parameter_flows(&mut self, file: &SwayFile) {
        // Track how parameters flow between functions
        let lines: Vec<&str> = file.content.lines().collect();
        
        for (func_name, func_info) in &self.fcg.functions {
            for param in &func_info.parameters {
                // Find where this parameter is used in function calls
                for line_num in func_info.line_start..func_info.line_end {
                    if line_num < lines.len() {
                        let line = lines[line_num];
                        
                        // If parameter is passed to another function
                        for called_func in &func_info.calls {
                            if line.contains(&format!("{}(", called_func)) && line.contains(param) {
                                let validation_context = self.extract_validation_context(
                                    &lines, 
                                    func_info.line_start, 
                                    line_num
                                );
                                
                                self.parameter_flows.push(ParameterFlow {
                                    parameter: param.clone(),
                                    source_function: func_name.clone(),
                                    target_function: called_func.clone(),
                                    validation_context,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn extract_validation_context(&self, lines: &[&str], func_start: usize, current_line: usize) -> Vec<String> {
        let mut validations = Vec::new();
        
        // Look for validation patterns between function start and current line
        for i in func_start..current_line {
            if i < lines.len() {
                let line = lines[i];
                if line.contains("require(") || line.contains("assert(") {
                    validations.push(line.trim().to_string());
                }
            }
        }
        
        validations
    }

    fn calculate_max_call_depth(&self) -> u32 {
        let mut max_depth = 0;
        
        for func_name in self.fcg.functions.keys() {
            let depth = self.calculate_call_depth_recursive(func_name, &mut HashSet::new());
            max_depth = max_depth.max(depth);
        }
        
        max_depth
    }

    fn calculate_call_depth_recursive(&self, func_name: &str, visited: &mut HashSet<String>) -> u32 {
        if visited.contains(func_name) {
            return 0; // Avoid infinite recursion
        }
        
        visited.insert(func_name.to_string());
        let mut max_depth = 0;
        
        if let Some(callees) = self.fcg.call_relationships.get(func_name) {
            for callee in callees {
                let depth = self.calculate_call_depth_recursive(callee, visited);
                max_depth = max_depth.max(depth);
            }
        }
        
        visited.remove(func_name);
        max_depth + 1
    }

    // Context Validity Checker (CVC) methods
    pub fn is_function_protected(&self, func_name: &str) -> bool {
        // Check direct protection
        if let Some(func_info) = self.fcg.functions.get(func_name) {
            if !func_info.access_controls.is_empty() {
                return true;
            }
        }
        
        // Check inherited protection
        self.fcg.protection_propagation.contains_key(func_name)
    }

    pub fn get_protection_chain(&self, func_name: &str) -> Vec<String> {
        let mut chain = Vec::new();
        
        if let Some(protections) = self.fcg.protection_propagation.get(func_name) {
            for protection in protections {
                chain.push(format!("{}:{}", protection.line, protection.condition));
            }
        }
        
        chain
    }

    pub fn should_flag_access_control(&self, func_name: &str) -> bool {
        // Only flag if:
        // 1. Function has no direct access control
        // 2. Function is public or has external calls/storage writes
        // 3. No caller provides protection
        
        if let Some(func_info) = self.fcg.functions.get(func_name) {
            // Has direct protection
            if !func_info.access_controls.is_empty() {
                return false;
            }
            
            // Private function with no risky operations
            if !func_info.is_public && !func_info.has_external_calls && !func_info.has_storage_write {
                return false;
            }
            
            // Check if protected through call chain
            if self.is_function_protected(func_name) {
                return false;
            }
            
            // Only flag risky public functions without protection
            return func_info.is_public && (func_info.has_external_calls || func_info.has_storage_write);
        }
        
        true // Default to flagging if we can't analyze
    }
} 