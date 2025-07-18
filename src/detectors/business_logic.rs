use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct BusinessLogicDetector;

// State inconsistency patterns
static STATE_INCONSISTENCY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"storage\.balance\.write\([^)]*\)\s*;\s*storage\.total_supply\.write\([^)]*\)").unwrap(), // Balance/supply mismatch
        Regex::new(r"storage\.\w+\.write\([^)]*\)\s*;[^;]*storage\.\w+\.write\([^)]*\)").unwrap(), // Multiple storage writes
        Regex::new(r"if\s*\([^)]*\)\s*\{[^}]*storage\.\w+\.write[^}]*\}\s*else\s*\{[^}]*storage\.\w+\.write").unwrap(), // Conditional state changes
    ]
});

// Business rule violation patterns
static BUSINESS_RULE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"transfer.*amount.*>.*balance").unwrap(), // Transfer more than balance
        Regex::new(r"mint.*without.*supply_check").unwrap(), // Unlimited minting
        Regex::new(r"withdraw.*without.*balance_check").unwrap(), // Withdraw without balance check
        Regex::new(r"burn.*amount.*>.*total_supply").unwrap(), // Burn more than total supply
    ]
});

// Time-based logic issues
static TIME_LOGIC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"block\.timestamp\s*[<>]=?\s*\w+\s*\+\s*\d+").unwrap(), // Time-based conditions
        Regex::new(r"require\s*\([^)]*timestamp[^)]*\)").unwrap(), // Timestamp requirements
        Regex::new(r"deadline.*<.*block\.timestamp").unwrap(), // Deadline logic
        Regex::new(r"lock_time.*timestamp").unwrap(), // Time locks
    ]
});

// Economic logic flaws
static ECONOMIC_LOGIC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"price\s*\*\s*amount\s*/\s*\d+").unwrap(), // Price calculations
        Regex::new(r"fee\s*=\s*amount\s*\*\s*\d+\s*/\s*\d+").unwrap(), // Fee calculations
        Regex::new(r"reward\s*=.*amount").unwrap(), // Reward calculations
        Regex::new(r"interest.*rate.*time").unwrap(), // Interest calculations
    ]
});

// Access pattern violations
static ACCESS_PATTERN_VIOLATIONS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"require\s*\(\s*msg\.sender\s*==\s*owner\s*\).*storage\.owner\.write").unwrap(), // Owner changing ownership
        Regex::new(r"transfer.*to.*msg\.sender").unwrap(), // Self-transfer
        Regex::new(r"approve.*msg\.sender").unwrap(), // Self-approval
    ]
});

// Critical operation sequences
static CRITICAL_SEQUENCES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"external_call.*storage\.\w+\.write").unwrap(), // External call before state change
        Regex::new(r"transfer.*abi\(").unwrap(), // Transfer before external call
        Regex::new(r"mint.*transfer").unwrap(), // Mint then immediate transfer
    ]
});

impl BusinessLogicDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_state_consistency(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for state inconsistency patterns
            for pattern in STATE_INCONSISTENCY_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::High,
                            Category::Security,
                            0.85,
                            "Potential State Inconsistency",
                            &format!(
                                "Multiple storage modifications detected that may lead to state inconsistency: {}. Ensure all related state variables are updated atomically.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 3),
                            "Implement atomic state updates and verify that all related storage variables maintain consistency. Consider using temporary variables and updating all state at once.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![362, 366]) // Race Condition, Race Condition within a Thread
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn analyze_business_rules(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for business rule violations
            for pattern in BUSINESS_RULE_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Critical,
                            Category::Security,
                            0.9,
                            "Business Rule Violation",
                            &format!(
                                "Potential violation of business logic rules: {}. This could lead to economic exploits or contract invariant violations.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Implement proper business rule validation: check balances before transfers, implement supply caps for minting, validate burn amounts against total supply.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![840, 670]) // Business Logic Errors, Always-Incorrect Control Flow Implementation
                        .with_effort(EstimatedEffort::Hard)
                    );
                }
            }

            // Check for economic logic flaws
            for pattern in ECONOMIC_LOGIC_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Medium,
                            Category::Security,
                            0.8,
                            "Economic Logic Flaw",
                            &format!(
                                "Potential economic calculation issue: {}. Verify mathematical operations for precision loss, overflow, and economic soundness.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Review economic calculations for precision, overflow protection, and business logic correctness. Consider using fixed-point arithmetic for financial calculations.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![682, 190]) // Incorrect Calculation, Integer Overflow
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn analyze_time_logic(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for time-based logic issues
            for pattern in TIME_LOGIC_PATTERNS.iter() {
                if let Some(captures) = pattern.find(line) {
                    let severity = if line.contains("deadline") || line.contains("lock_time") {
                        Severity::High // Time-sensitive operations
                    } else {
                        Severity::Medium
                    };

                    findings.push(
                        Finding::new(
                            self.name(),
                            severity,
                            Category::Security,
                            0.75,
                            "Time-Based Logic Vulnerability",
                            &format!(
                                "Time-dependent logic detected: {}. Block timestamp can be manipulated by miners within certain bounds (±15 seconds).",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Avoid strict dependence on block.timestamp for critical logic. Use block numbers for relative time or implement tolerance ranges for timestamp-based conditions.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![367]) // Time-of-check Time-of-use (TOCTOU) Race Condition
                        .with_effort(EstimatedEffort::Medium)
                    );
                }
            }
        }

        findings
    }

    fn analyze_access_patterns(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for access pattern violations
            for pattern in ACCESS_PATTERN_VIOLATIONS.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::Medium,
                            Category::Security,
                            0.8,
                            "Suspicious Access Pattern",
                            &format!(
                                "Potentially problematic access pattern: {}. This might indicate logical errors or unintended behavior.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 2),
                            "Review the access pattern logic. Ensure that self-operations (like self-transfer or self-approval) are intentional and properly handled.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![840]) // Business Logic Errors
                        .with_effort(EstimatedEffort::Easy)
                    );
                }
            }

            // Check for critical operation sequences
            for pattern in CRITICAL_SEQUENCES.iter() {
                if let Some(captures) = pattern.find(line) {
                    findings.push(
                        Finding::new(
                            self.name(),
                            Severity::High,
                            Category::Security,
                            0.85,
                            "Critical Operation Sequence",
                            &format!(
                                "Critical operation sequence detected: {}. The order of operations may create vulnerabilities or unexpected behavior.",
                                captures.as_str()
                            ),
                            &file.path,
                            line_num,
                            captures.start(),
                            extract_code_snippet(&file.content, line_num, 3),
                            "Review the order of operations. Follow checks-effects-interactions pattern: validate inputs, update state, then perform external interactions.",
                        )
                        .with_context(context.clone())
                        .with_cwe(vec![362, 670]) // Race Condition, Always-Incorrect Control Flow
                        .with_effort(EstimatedEffort::Hard)
                    );
                }
            }
        }

        findings
    }

    fn analyze_loop_logic(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for unbounded loops
            if line.contains("while") && !line.contains("counter") && !line.contains("limit") {
                findings.push(
                    Finding::new(
                        self.name(),
                        Severity::Medium,
                        Category::Security,
                        0.7,
                        "Potentially Unbounded Loop",
                        "While loop without explicit bounds checking detected. This could lead to gas exhaustion or DoS conditions.",
                        &file.path,
                        line_num,
                        0,
                        extract_code_snippet(&file.content, line_num, 2),
                        "Add explicit bounds checking, iteration limits, or use bounded data structures to prevent gas exhaustion attacks.",
                    )
                    .with_context(context.clone())
                    .with_cwe(vec![834, 400]) // Excessive Iteration, Uncontrolled Resource Consumption
                    .with_effort(EstimatedEffort::Medium)
                );
            }

            // Check for loops with external calls
            if (line.contains("for") || line.contains("while")) && line.contains("call") {
                findings.push(
                    Finding::new(
                        self.name(),
                        Severity::High,
                        Category::Security,
                        0.85,
                        "External Call in Loop",
                        "Loop containing external calls detected. This pattern can lead to gas exhaustion, reentrancy attacks, or DoS conditions.",
                        &file.path,
                        line_num,
                        0,
                        extract_code_snippet(&file.content, line_num, 2),
                        "Avoid external calls in loops. Use pull-over-push pattern, batch operations, or implement proper gas limits and bounds checking.",
                    )
                    .with_context(context.clone())
                    .with_cwe(vec![834, 841]) // Excessive Iteration, Improper Enforcement of Behavioral Workflow
                    .with_effort(EstimatedEffort::Hard)
                );
            }
        }

        findings
    }
}

impl Detector for BusinessLogicDetector {
    fn name(&self) -> &'static str {
        "business_logic"
    }
    
    fn description(&self) -> &'static str {
        "Identifies business logic vulnerabilities, state inconsistencies, and economic flaws"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Analyze state consistency
        all_findings.extend(self.analyze_state_consistency(file, context));
        
        // Analyze business rules
        all_findings.extend(self.analyze_business_rules(file, context));
        
        // Analyze time-based logic
        all_findings.extend(self.analyze_time_logic(file, context));
        
        // Analyze access patterns
        all_findings.extend(self.analyze_access_patterns(file, context));
        
        // Analyze loop logic
        all_findings.extend(self.analyze_loop_logic(file, context));
        
        Ok(all_findings)
    }
} 