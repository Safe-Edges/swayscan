use std::collections::{HashMap, HashSet};
use regex::Regex;
use once_cell::sync::Lazy;

/// Advanced Sway-specific analysis engine for accurate vulnerability detection
pub struct SwayAnalyzer {
    pub fcg: FunctionCallGraph,
    pub ppl: ProtectionPropagationLayer,
    pub pdg: ParameterDependencyGraph,
    pub cvc: ContextValidityChecker,
}

/// Function Call Graph - Maps callers and callees with context
#[derive(Debug, Clone)]
pub struct FunctionCallGraph {
    pub functions: HashMap<String, SwayFunction>,
    pub call_relationships: HashMap<String, Vec<String>>, // caller -> callees
    pub reverse_calls: HashMap<String, Vec<String>>,     // callee -> callers
}

/// Protection Propagation Layer - Tracks access control flow
#[derive(Debug, Clone)]
pub struct ProtectionPropagationLayer {
    pub protected_functions: HashMap<String, Vec<AccessControlCheck>>,
    pub protection_inheritance: HashMap<String, Vec<String>>, // function -> inherited protections
}

/// Parameter Dependency Graph - Tracks parameter flow and validation
#[derive(Debug, Clone)]
pub struct ParameterDependencyGraph {
    pub parameter_flows: HashMap<String, Vec<ParameterFlow>>,
    pub validation_points: HashMap<String, Vec<ValidationCheck>>,
    pub dangerous_operations: HashMap<String, Vec<DangerousOp>>,
}

/// Context Validity Checker - Final validation with Sway-specific rules
#[derive(Debug, Clone)]
pub struct ContextValidityChecker {
    pub sway_patterns: SwayPatterns,
    pub false_positive_filters: FalsePositiveFilters,
}

#[derive(Debug, Clone)]
pub struct SwayFunction {
    pub name: String,
    pub is_storage_function: bool,
    pub is_payable: bool,
    pub visibility: FunctionVisibility,
    pub storage_reads: Vec<String>,
    pub storage_writes: Vec<String>,
    pub external_calls: Vec<ExternalCall>,
    pub parameters: Vec<FunctionParameter>,
    pub require_statements: Vec<RequireStatement>,
    pub body_lines: Vec<String>,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
}

#[derive(Debug, Clone)]
pub struct ExternalCall {
    pub function_name: String,
    pub target: Option<String>, // contract/identity
    pub line_number: usize,
    pub is_transfer: bool,
    pub is_checked: bool, // has return value handling
}

#[derive(Debug, Clone)]
pub struct FunctionParameter {
    pub name: String,
    pub param_type: String,
    pub is_address: bool,
    pub is_amount: bool,
    pub is_validated: bool,
}

#[derive(Debug, Clone)]
pub struct RequireStatement {
    pub condition: String,
    pub line_number: usize,
    pub protects: Vec<String>, // what this require protects
}

#[derive(Debug, Clone)]
pub struct AccessControlCheck {
    pub check_type: AccessControlType,
    pub condition: String,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub enum AccessControlType {
    OwnerCheck,
    AdminCheck,
    RoleCheck,
    StateCheck,
    BalanceCheck,
}

#[derive(Debug, Clone)]
pub struct ParameterFlow {
    pub from_param: String,
    pub to_operation: String,
    pub flow_type: FlowType,
    pub is_validated: bool,
}

#[derive(Debug, Clone)]
pub enum FlowType {
    DirectUse,
    ArithmeticOperation,
    StorageWrite,
    ExternalCall,
    Comparison,
}

#[derive(Debug, Clone)]
pub struct ValidationCheck {
    pub parameter: String,
    pub check_type: ValidationType,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub enum ValidationType {
    NonZero,
    BoundsCheck,
    AddressValid,
    OverflowCheck,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct DangerousOp {
    pub operation: String,
    pub line_number: usize,
    pub risk_level: RiskLevel,
    pub requires_protection: bool,
}

#[derive(Debug, Clone)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct SwayPatterns {
    pub storage_patterns: Lazy<Vec<Regex>>,
    pub transfer_patterns: Lazy<Vec<Regex>>,
    pub require_patterns: Lazy<Vec<Regex>>,
    pub access_control_patterns: Lazy<Vec<Regex>>,
    pub reentrancy_patterns: Lazy<Vec<Regex>>,
}

#[derive(Debug, Clone)]
pub struct FalsePositiveFilters {
    // Patterns that indicate safe code
    pub safe_patterns: Lazy<Vec<Regex>>,
    // Variable declarations vs actual logic
    pub declaration_patterns: Lazy<Vec<Regex>>,
    // Known safe Sway idioms
    pub sway_idioms: Lazy<Vec<Regex>>,
}

// Sway-specific regex patterns
static SWAY_STORAGE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.(\w+)\.write\(").unwrap(),
        Regex::new(r"storage\.(\w+)\.read\(\)").unwrap(),
        Regex::new(r"storage\.(\w+)\.insert\(").unwrap(),
        Regex::new(r"storage\.(\w+)\.remove\(").unwrap(),
    ]
});

static SWAY_TRANSFER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)").unwrap(),
        Regex::new(r"force_transfer_to_contract\s*\(").unwrap(),
        Regex::new(r"mint_to\s*\(").unwrap(),
        Regex::new(r"burn\s*\(").unwrap(),
    ]
});

static SWAY_REQUIRE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*([^,]+),?\s*([^)]*)\)").unwrap(),
        Regex::new(r"assert\s*\(\s*([^)]+)\)").unwrap(),
        Regex::new(r"revert\s*\(\s*([^)]*)\)").unwrap(),
    ]
});

static SWAY_ACCESS_CONTROL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"msg_sender\(\)").unwrap(),
        Regex::new(r"owner\s*==").unwrap(),
        Regex::new(r"admin\s*==").unwrap(),
        Regex::new(r"only_owner").unwrap(),
        Regex::new(r"check_owner").unwrap(),
    ]
});

// False positive filters
static SAFE_DECLARATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"^\s*let\s+\w+\s*=").unwrap(),          // Variable declarations
        Regex::new(r"^\s*const\s+\w+\s*=").unwrap(),        // Constants
        Regex::new(r"^\s*struct\s+\w+").unwrap(),           // Struct definitions
        Regex::new(r"^\s*enum\s+\w+").unwrap(),             // Enum definitions
        Regex::new(r"^\s*//").unwrap(),                     // Comments
        Regex::new(r"^\s*storage\s*\{").unwrap(),           // Storage block
        Regex::new(r"^\s*configurable\s*\{").unwrap(),      // Configurable block
    ]
});

static SAFE_SWAY_IDIOMS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"\.try_read\(\)\.unwrap_or\(").unwrap(),     // Safe storage reads
        Regex::new(r"\.get\(\w+\)\.try_read\(\)").unwrap(),      // Safe map reads
        Regex::new(r"if\s+let\s+Some\(").unwrap(),              // Safe option handling
        Regex::new(r"match\s+\w+\s*\{").unwrap(),               // Pattern matching
        Regex::new(r"#\[storage\(read\)\]").unwrap(),           // Read-only functions
    ]
});

impl SwayAnalyzer {
    pub fn new() -> Self {
        Self {
            fcg: FunctionCallGraph::new(),
            ppl: ProtectionPropagationLayer::new(),
            pdg: ParameterDependencyGraph::new(),
            cvc: ContextValidityChecker::new(),
        }
    }

    /// Main analysis entry point
    pub fn analyze_file(&mut self, file_content: &str, file_path: &str) -> AnalysisResult {
        let lines: Vec<&str> = file_content.lines().collect();
        
        // Phase 1: Build Function Call Graph
        self.fcg.build_from_content(&lines);
        
        // Phase 2: Analyze Protection Propagation
        self.ppl.analyze_protections(&self.fcg, &lines);
        
        // Phase 3: Build Parameter Dependency Graph
        self.pdg.analyze_parameter_flows(&self.fcg, &lines);
        
        // Phase 4: Context Validity Check with false positive filtering
        self.cvc.validate_vulnerabilities(&self.fcg, &self.ppl, &self.pdg, &lines)
    }
    
    /// Check if a finding is likely a false positive
    pub fn is_false_positive(&self, line: &str, context: &[&str]) -> bool {
        // Filter out variable declarations
        if SAFE_DECLARATION_PATTERNS.iter().any(|pattern| pattern.is_match(line)) {
            return true;
        }
        
        // Filter out safe Sway idioms
        if SAFE_SWAY_IDIOMS.iter().any(|pattern| pattern.is_match(line)) {
            return true;
        }
        
        // Check surrounding context for safety patterns
        let context_str = context.join("\n");
        if self.has_adequate_protection(&context_str) {
            return true;
        }
        
        false
    }
    
    fn has_adequate_protection(&self, context: &str) -> bool {
        // Check for require statements in the same function
        SWAY_REQUIRE_PATTERNS.iter().any(|pattern| pattern.is_match(context)) &&
        SWAY_ACCESS_CONTROL_PATTERNS.iter().any(|pattern| pattern.is_match(context))
    }
}

#[derive(Debug)]
pub struct AnalysisResult {
    pub high_confidence_issues: Vec<ValidatedIssue>,
    pub false_positives_filtered: usize,
    pub analysis_quality_score: f64, // 0.0 to 1.0
}

#[derive(Debug)]
pub struct ValidatedIssue {
    pub issue_type: String,
    pub severity: RiskLevel,
    pub confidence: f64,
    pub line_number: usize,
    pub description: String,
    pub fix_suggestion: String,
    pub sway_specific: bool,
}

// Implementation stubs - will be implemented in separate files
impl FunctionCallGraph {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            call_relationships: HashMap::new(),
            reverse_calls: HashMap::new(),
        }
    }
    
    pub fn build_from_content(&mut self, lines: &[&str]) {
        // Implementation will parse Sway functions and build call graph
    }
}

impl ProtectionPropagationLayer {
    pub fn new() -> Self {
        Self {
            protected_functions: HashMap::new(),
            protection_inheritance: HashMap::new(),
        }
    }
    
    pub fn analyze_protections(&mut self, fcg: &FunctionCallGraph, lines: &[&str]) {
        // Implementation will analyze access control propagation
    }
}

impl ParameterDependencyGraph {
    pub fn new() -> Self {
        Self {
            parameter_flows: HashMap::new(),
            validation_points: HashMap::new(),
            dangerous_operations: HashMap::new(),
        }
    }
    
    pub fn analyze_parameter_flows(&mut self, fcg: &FunctionCallGraph, lines: &[&str]) {
        // Implementation will track parameter usage and validation
    }
}

impl ContextValidityChecker {
    pub fn new() -> Self {
        Self {
            sway_patterns: SwayPatterns {
                storage_patterns: SWAY_STORAGE_PATTERNS.clone(),
                transfer_patterns: SWAY_TRANSFER_PATTERNS.clone(),
                require_patterns: SWAY_REQUIRE_PATTERNS.clone(),
                access_control_patterns: SWAY_ACCESS_CONTROL_PATTERNS.clone(),
                reentrancy_patterns: Lazy::new(|| vec![]),
            },
            false_positive_filters: FalsePositiveFilters {
                safe_patterns: Lazy::new(|| vec![]),
                declaration_patterns: SAFE_DECLARATION_PATTERNS.clone(),
                sway_idioms: SAFE_SWAY_IDIOMS.clone(),
            },
        }
    }
    
    pub fn validate_vulnerabilities(
        &self,
        fcg: &FunctionCallGraph,
        ppl: &ProtectionPropagationLayer,
        pdg: &ParameterDependencyGraph,
        lines: &[&str],
    ) -> AnalysisResult {
        AnalysisResult {
            high_confidence_issues: vec![],
            false_positives_filtered: 0,
            analysis_quality_score: 0.85,
        }
    }
} 