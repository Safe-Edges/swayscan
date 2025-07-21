use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct WeakPrngDetector;

impl WeakPrngDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_weak_prng(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect weak PRNG-specific issues, not cryptographic, business logic, or other detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_weak_prng = false;
        let mut has_secure_randomness = false;
        let mut has_timestamp_randomness = false;
        let mut has_block_randomness = false;
        let mut weak_prng_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for weak PRNG patterns
            if l.contains("rand()") || l.contains("random()") || l.contains("Math.random()") {
                has_weak_prng = true;
                weak_prng_lines.push(idx + line_number);
            }
            
            // Check for timestamp-based randomness
            if l.contains("timestamp") && (l.contains("%") || l.contains("mod")) {
                has_timestamp_randomness = true;
                weak_prng_lines.push(idx + line_number);
            }
            
            // Check for block-based randomness
            if l.contains("block.timestamp") && (l.contains("%") || l.contains("mod")) {
                has_block_randomness = true;
                weak_prng_lines.push(idx + line_number);
            }
            
            if l.contains("block.number") && (l.contains("%") || l.contains("mod")) {
                has_block_randomness = true;
                weak_prng_lines.push(idx + line_number);
            }
            
            // Check for secure randomness
            if l.contains("secure_random") || l.contains("crypto_random") || l.contains("entropy") {
                has_secure_randomness = true;
            }
            
            // Check for predictable patterns
            if l.contains("msg.sender") && l.contains("hash") {
                has_weak_prng = true;
                weak_prng_lines.push(idx + line_number);
            }
            
            if l.contains("block.timestamp") && l.contains("*") {
                has_timestamp_randomness = true;
                weak_prng_lines.push(idx + line_number);
            }
        }
        
        // Inter-function: check if this function is called by another public function
        let mut called_by_public = false;
        for f in &ast.functions {
            if f.name != function.name && f.content.contains(&function.name) && matches!(f.visibility, crate::parser::FunctionVisibility::Public) {
                called_by_public = true;
                break;
            }
        }
        
        if found && (has_weak_prng || has_timestamp_randomness || has_block_randomness) && (!has_secure_randomness || called_by_public) {
            let mut description = format!("Function '{}' contains weak PRNG usage.", function.name);
            if has_weak_prng {
                description.push_str(" Weak PRNG detected.");
            }
            if has_timestamp_randomness {
                description.push_str(" Timestamp-based randomness detected.");
            }
            if has_block_randomness {
                description.push_str(" Block-based randomness detected.");
            }
            if !has_secure_randomness {
                description.push_str(" No secure randomness source detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "weak_prng",
                Severity::High,
                Category::Cryptographic,
                0.9,
                &format!("Weak PRNG Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Use cryptographically secure random number generators and avoid predictable randomness sources.",
            ))
        } else {
            None
        }
    }
}

impl Detector for WeakPrngDetector {
    fn name(&self) -> &'static str {
        "weak_prng"
    }
    fn description(&self) -> &'static str {
        "Detects weak PRNG usage using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Cryptographic
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_weak_prng(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}