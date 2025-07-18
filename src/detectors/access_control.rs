use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext, extract_code_snippet, Reference, ReferenceType, EstimatedEffort};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub struct AccessControlDetector;

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

impl AccessControlDetector {
    pub fn new() -> Self {
        Self
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
        "Detects missing or weak access controls that could allow unauthorized access to critical functions"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut all_findings = Vec::new();
        
        // Analyze for missing access control
        all_findings.extend(self.analyze_missing_access_control(file, context));
        
        // Analyze for weak access control patterns
        all_findings.extend(self.analyze_weak_access_control(file, context));
        
        Ok(all_findings)
    }
} 