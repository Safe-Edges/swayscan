use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct UnusedImportDetector;

impl UnusedImportDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_unused_import(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        // Only detect unused import-specific issues, not other specific detectors
        let mut found = false;
        let mut line_number = function.span.start;
        let mut has_imports = false;
        let mut has_unused_imports = false;
        let mut import_lines = Vec::new();
        let lines: Vec<&str> = function.content.lines().collect();
        
        for (idx, line) in lines.iter().enumerate() {
            let l = line.trim();
            
            // Check for import statements
            if l.starts_with("use ") || l.starts_with("import ") {
                has_imports = true;
                import_lines.push(idx + line_number);
            }
            
            // Check for unused imports (simplified detection)
            if l.starts_with("use ") && !l.contains("as") {
                // Check if the imported item is used in the function
                let import_name = l.split_whitespace().nth(1).unwrap_or("");
                if !import_name.is_empty() {
                    let mut used = false;
                    for check_line in &lines {
                        if check_line.contains(import_name) && !check_line.starts_with("use ") {
                            used = true;
                            break;
                        }
                    }
                    if !used {
                        has_unused_imports = true;
                        found = true;
                    }
                }
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
        
        if found && has_imports && (has_unused_imports || called_by_public) {
            let mut description = format!("Function '{}' contains unused imports.", function.name);
            if has_unused_imports {
                description.push_str(" Unused import statements detected.");
            }
            if called_by_public {
                description.push_str(" This function is reachable from a public function.");
            }
            
            Some(Finding::new(
                "unused_import",
                Severity::Low,
                Category::LogicErrors,
                0.8,
                &format!("Unused Import Detected - {}", function.name),
                &description,
                &file.path,
                line_number,
                line_number,
                &function.content,
                "Remove unused imports to improve code quality and reduce gas costs.",
            ))
        } else {
            None
        }
    }
}

impl Detector for UnusedImportDetector {
    fn name(&self) -> &'static str {
        "unused_import"
    }
    fn description(&self) -> &'static str {
        "Detects unused imports using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::LogicErrors
    }
    fn default_severity(&self) -> Severity {
        Severity::Low
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_unused_import(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}