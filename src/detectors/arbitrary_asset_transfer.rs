use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::SwayFile;
use regex::Regex;
use once_cell::sync::Lazy;

static TRANSFER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Standard transfer functions
        Regex::new(r"transfer\s*\(\s*(\w+)\s*,\s*([^,\)]+)\s*,\s*([^,\)]+)\s*\)").unwrap(),
        // Mint operations
        Regex::new(r"mint\s*\(\s*(\w+)\s*,\s*([^,\)]+)\s*,\s*([^,\)]+)\s*\)").unwrap(),
        Regex::new(r"mint_to\s*\(\s*(\w+)\s*,\s*([^,\)]+)\s*,\s*([^,\)]+)\s*\)").unwrap(),
        // Force transfer patterns
        Regex::new(r"force_transfer_to_contract\s*\(").unwrap(),
        // Asset management
        Regex::new(r"this_balance\s*\(\s*([^)]+)\s*\)").unwrap(),
    ]
});

static ACCESS_CONTROL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Common access control checks
        Regex::new(r"require\s*\(\s*msg_sender\(\)").unwrap(),
        Regex::new(r"assert\s*\(\s*msg_sender\(\)").unwrap(),
        Regex::new(r"only_owner\s*\(\s*\)").unwrap(),
        Regex::new(r"is_admin\s*\(").unwrap(),
        Regex::new(r"has_role\s*\(").unwrap(),
        Regex::new(r"check_permission\s*\(").unwrap(),
    ]
});

pub struct ArbitraryAssetTransferDetector;

impl ArbitraryAssetTransferDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_transfer_functions(&self, file: &SwayFile, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();
        let mut current_function: Option<String> = None;
        let mut current_function_start: usize = 0;
        let mut brace_depth = 0;
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_number = line_num + 1;
            let trimmed = line.trim();
            
            // Track function boundaries
            if trimmed.starts_with("fn ") {
                current_function = self.extract_function_name(trimmed);
                current_function_start = line_num;
                brace_depth = 0;
            }
            
            // Track brace depth
            brace_depth += line.matches('{').count() as i32;
            brace_depth -= line.matches('}').count() as i32;
            
            // Reset function when we exit
            if brace_depth <= 0 && current_function.is_some() && line_num > current_function_start {
                current_function = None;
            }
            
            // Check for transfer operations
            for pattern in TRANSFER_PATTERNS.iter() {
                if pattern.is_match(line) {
                    if let Some(ref func_name) = current_function {
                        // Check if this function has access control
                        let has_access_control = self.function_has_access_control(
                            &lines, 
                            current_function_start, 
                            line_num
                        );
                        
                        if !has_access_control {
                            let severity = self.determine_severity(line, func_name);
                            let confidence = self.calculate_confidence(line, func_name, &has_access_control);
                            
                            let finding = Finding::new(
                                "arbitrary_asset_transfer",
                                severity,
                                Category::Security,
                                confidence,
                                "Arbitrary Asset Transfer Without Access Control",
                                format!(
                                    "Function '{}' at line {} transfers assets to arbitrary addresses without \
                                    proper access control. This allows anyone to call the function and \
                                    potentially drain contract assets.",
                                    func_name, line_number
                                ),
                                &file.path,
                                line_number,
                                0,
                                line.trim(),
                                "Implement proper access control mechanisms: (1) Add require() statements to \
                                verify msg.sender() authority, (2) Use role-based access control (RBAC), \
                                (3) Implement ownership patterns, (4) Add multi-signature requirements for \
                                high-value transfers."
                            )
                            .with_context(context.clone())
                            .with_cwe(vec![284, 863, 862]) // CWE-284: Improper Access Control, CWE-863: Incorrect Authorization, CWE-862: Missing Authorization
                            .with_impact(
                                "Attackers can exploit this vulnerability to drain contract assets, \
                                transfer funds to unauthorized addresses, or manipulate asset balances, \
                                leading to significant financial losses."
                            );
                            
                            findings.push(finding);
                        }
                    }
                }
            }
        }
        
        findings
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
    
    fn function_has_access_control(&self, lines: &[&str], func_start: usize, transfer_line: usize) -> bool {
        // Check for access control patterns within the function before the transfer
        for i in func_start..=transfer_line {
            if i < lines.len() {
                let line = lines[i];
                for pattern in ACCESS_CONTROL_PATTERNS.iter() {
                    if pattern.is_match(line) {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    fn determine_severity(&self, line: &str, func_name: &str) -> Severity {
        let line_lower = line.to_lowercase();
        let func_lower = func_name.to_lowercase();
        
        // Critical if it's a privileged operation
        if func_lower.contains("admin") || func_lower.contains("owner") || 
           func_lower.contains("mint") || func_lower.contains("burn") ||
           line_lower.contains("mint") || line_lower.contains("force_transfer") {
            return Severity::Critical;
        }
        
        // High if it involves large amounts or is unrestricted
        if func_lower.contains("emergency") || func_lower.contains("rescue") ||
           line_lower.contains("this_balance") {
            return Severity::High;
        }
        
        // Medium for regular transfers without access control
        Severity::High
    }
    
    fn calculate_confidence(&self, line: &str, func_name: &str, has_access_control: &bool) -> f64 {
        let mut confidence: f64 = 0.7;
        
        // Higher confidence if no access control at all
        if !has_access_control {
            confidence += 0.2;
        }
        
        // Higher confidence for clearly privileged operations
        let line_lower = line.to_lowercase();
        let func_lower = func_name.to_lowercase();
        
        if func_lower.contains("admin") || func_lower.contains("mint") || 
           line_lower.contains("mint") || line_lower.contains("force") {
            confidence += 0.1;
        }
        
        confidence.min(1.0)
    }
}

impl Detector for ArbitraryAssetTransferDetector {
    fn name(&self) -> &'static str {
        "arbitrary_asset_transfer"
    }
    
    fn description(&self) -> &'static str {
        "Detects functions that transfer native assets to arbitrary addresses without proper access restrictions"
    }
    
    fn category(&self) -> Category {
        Category::Security
    }
    
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        Ok(self.analyze_transfer_functions(file, context))
    }
}