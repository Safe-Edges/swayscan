use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct UnusedImportDetector;

impl UnusedImportDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_unused_import(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        use crate::parser::{StatementKind, ExpressionKind, SwayStatement, SwayExpression};
        
        #[derive(Debug)]
        struct ImportInfo {
            full_path: String,
            local_name: String,
            is_used: bool,
            line: usize,
        }
        
        #[derive(Debug)]
        struct ImportState {
            imports: Vec<ImportInfo>,
            used_symbols: Vec<String>,
            module_imports: Vec<String>,
            std_imports: Vec<String>,
        }
        
        impl ImportState {
            fn new() -> Self {
                Self {
                    imports: Vec::new(),
                    used_symbols: Vec::new(),
                    module_imports: Vec::new(),
                    std_imports: Vec::new(),
                }
            }
            
            fn add_import(&mut self, import_line: &str, line_num: usize) {
                let trimmed = import_line.trim();
                if !trimmed.starts_with("use ") {
                    return;
                }
                
                // Parse complex Sway import patterns
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() < 2 {
                    return;
                }
                
                // Handle different import patterns
                if parts.len() == 2 {
                    // Simple: use std::auth::msg_sender;
                    let path = parts[1].trim_end_matches(';');
                    if let Some(local_name) = path.split("::").last() {
                        self.imports.push(ImportInfo {
                            full_path: path.to_string(),
                            local_name: local_name.to_string(),
                            is_used: false,
                            line: line_num,
                        });
                        
                        // Track std imports separately
                        if path.starts_with("std::") {
                            self.std_imports.push(local_name.to_string());
                        }
                    }
                } else if parts.len() >= 4 && parts[2] == "as" {
                    // Aliased: use std::auth::msg_sender as sender;
                    let path = parts[1];
                    let alias = parts[3].trim_end_matches(';');
                    self.imports.push(ImportInfo {
                        full_path: path.to_string(),
                        local_name: alias.to_string(),
                        is_used: false,
                        line: line_num,
                    });
                } else if parts.len() >= 3 && parts[1] == "{" {
                    // Multiple: use std::auth::{msg_sender, require};
                    let module_path = parts[0];
                    let mut in_braces = false;
                    let mut brace_content = String::new();
                    
                    for part in &parts[2..] {
                        let part = part.trim_end_matches(';');
                        if part == "{" {
                            in_braces = true;
                        } else if part == "}" {
                            in_braces = false;
                            break;
                        } else if in_braces {
                            if !brace_content.is_empty() {
                                brace_content.push(',');
                            }
                            brace_content.push_str(part);
                        }
                    }
                    
                    // Parse individual imports from braces
                    for import_name in brace_content.split(',') {
                        let import_name = import_name.trim();
                        if !import_name.is_empty() {
                            self.imports.push(ImportInfo {
                                full_path: format!("{}::{}", module_path, import_name),
                                local_name: import_name.to_string(),
                                is_used: false,
                                line: line_num,
                            });
                        }
                    }
                }
            }
            
            fn check_symbol_usage(&mut self, symbol: &str) {
                // Check exact matches first
                for import in &mut self.imports {
                    if import.local_name == symbol {
                        import.is_used = true;
                        return;
                    }
                }
                
                // Check qualified path usage (e.g., std::auth::msg_sender)
                for import in &mut self.imports {
                    if import.full_path.ends_with(symbol) || import.full_path == symbol {
                        import.is_used = true;
                        return;
                    }
                }
                
                // Check if it's a known std library function
                if self.std_imports.contains(&symbol.to_string()) {
                    // Mark corresponding std import as used
                    for import in &mut self.imports {
                        if import.full_path.starts_with("std::") && import.local_name == symbol {
                            import.is_used = true;
                            return;
                        }
                    }
                }
                
                // Track as used symbol for context
                if !self.used_symbols.contains(&symbol.to_string()) {
                    self.used_symbols.push(symbol.to_string());
                }
            }
            
            fn get_unused_imports(&self) -> Vec<&ImportInfo> {
                self.imports.iter().filter(|import| !import.is_used).collect()
            }
        }
        
        fn walk_for_import_usage(stmts: &[SwayStatement], state: &mut ImportState) {
            for stmt in stmts {
                match &stmt.kind {
                    StatementKind::Expression(expr) => {
                        walk_expr_for_import_usage(expr, state);
                    }
                    StatementKind::Let(let_stmt) => {
                        walk_expr_for_import_usage(&let_stmt.value, state);
                    }
                    StatementKind::Return(expr_opt) => {
                        if let Some(expr) = expr_opt {
                            walk_expr_for_import_usage(expr, state);
                        }
                    }
                    StatementKind::If(if_stmt) => {
                        walk_expr_for_import_usage(&if_stmt.condition, state);
                        walk_for_import_usage(&if_stmt.then_block, state);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_import_usage(else_block, state);
                        }
                    }
                    StatementKind::While(while_stmt) => {
                        walk_expr_for_import_usage(&while_stmt.condition, state);
                        walk_for_import_usage(&while_stmt.body, state);
                    }
                    StatementKind::For(for_stmt) => {
                        walk_expr_for_import_usage(&for_stmt.iterator, state);
                        walk_for_import_usage(&for_stmt.body, state);
                    }
                    StatementKind::Match(match_stmt) => {
                        walk_expr_for_import_usage(&match_stmt.expression, state);
                        for arm in &match_stmt.arms {
                            walk_for_import_usage(&arm.body, state);
                        }
                    }
                    StatementKind::Block(stmts) => walk_for_import_usage(stmts, state),
                    _ => {}
                }
            }
        }
        
        fn walk_expr_for_import_usage(expr: &SwayExpression, state: &mut ImportState) {
            use ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    // Check function name usage
                    let func_name = call.function.as_str();
                    state.check_symbol_usage(func_name);
                    
                    // Check arguments
                    for arg in &call.arguments {
                        walk_expr_for_import_usage(arg, state);
                    }
                }
                MethodCall(mc) => {
                    // Check method name usage
                    let method_name = mc.method.as_str();
                    state.check_symbol_usage(method_name);
                    
                    // Check receiver and arguments
                    walk_expr_for_import_usage(&mc.receiver, state);
                    for arg in &mc.arguments {
                        walk_expr_for_import_usage(arg, state);
                    }
                }
                Variable(var_name) => {
                    // Check variable name usage (but be more careful about built-ins)
                    if !is_built_in_symbol(var_name) {
                        state.check_symbol_usage(var_name);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_import_usage(&bin.left, state);
                    walk_expr_for_import_usage(&bin.right, state);
                }
                Unary(u) => walk_expr_for_import_usage(&u.operand, state),
                If(if_expr) => {
                    walk_expr_for_import_usage(&if_expr.condition, state);
                    walk_expr_for_import_usage(&if_expr.then_expr, state);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_import_usage(else_expr, state);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_import_usage(&match_expr.expression, state);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_import_usage(e, state);
                            }
                        }
                    }
                }
                Block(stmts) => walk_for_import_usage(stmts, state),
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_import_usage(e, state);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_import_usage(&f.value, state);
                    }
                }
                Index(idx) => {
                    walk_expr_for_import_usage(&idx.array, state);
                    walk_expr_for_import_usage(&idx.index, state);
                }
                Field(fe) => walk_expr_for_import_usage(&fe.receiver, state),
                Parenthesized(e) => walk_expr_for_import_usage(e, state),
                _ => {}
            }
        }
        
        fn is_built_in_symbol(symbol: &str) -> bool {
            let built_ins = [
                "true", "false", "None", "Some", "Ok", "Err",
                "u8", "u16", "u32", "u64", "u128", "u256",
                "i8", "i16", "i32", "i64", "i128", "i256",
                "b256", "Address", "Identity", "Bytes", "String",
                "Vec", "Option", "Result", "bool", "str",
                "self", "Self", "super", "crate", "extern",
                "as", "break", "const", "continue", "else", "enum",
                "fn", "for", "if", "impl", "in", "let", "loop",
                "match", "mod", "move", "mut", "pub", "ref",
                "return", "static", "struct", "trait", "type",
                "unsafe", "use", "where", "while", "async", "await",
                "dyn", "abstract", "become", "box", "do", "final",
                "macro", "override", "priv", "try", "typeof",
                "unsized", "virtual", "yield", "macro_rules",
                "union", "static", "const", "extern", "crate",
                "super", "self", "Self", "as", "async", "await",
                "break", "const", "continue", "crate", "dyn",
                "else", "enum", "extern", "false", "fn", "for",
                "if", "impl", "in", "let", "loop", "match", "mod",
                "move", "mut", "pub", "ref", "return", "self",
                "Self", "static", "struct", "super", "trait",
                "true", "type", "unsafe", "use", "where", "while",
                "async", "await", "try", "macro", "union",
            ];
            built_ins.contains(&symbol)
        }
        
        // Initialize import state
        let mut state = ImportState::new();
        
        // Parse imports from file content with line numbers
        for (line_num, line) in file.content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") {
                state.add_import(trimmed, line_num + 1);
            }
        }
        
        // Skip analysis if no imports found
        if state.imports.is_empty() {
            return None;
        }
        
        // Walk the function body to find usage
        walk_for_import_usage(&function.body, &mut state);
        
        // Get unused imports
        let unused_imports = state.get_unused_imports();
        
        // Only flag if there are unused imports and function is public/reachable
        if !unused_imports.is_empty() && Self::should_check_function(function, ast) {
            let unused_names: Vec<String> = unused_imports
                .iter()
                .map(|import| import.local_name.clone())
                .collect();
            
            let description = format!(
                "Function '{}' contains unused imports: {}.",
                function.name,
                unused_names.join(", ")
            );
            
            return Some(Finding::new(
                "unused_import",
                Severity::Low,
                Category::LogicErrors,
                0.9, // Higher confidence due to advanced AST analysis
                &format!("Unused Import Detected - {}", function.name),
                &description,
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Remove unused imports to improve code quality and reduce gas costs. Consider using 'cargo fix' to automatically remove unused imports.",
            ));
        }
        
        None
    }
}

impl UnusedImportDetector {
    fn should_check_function(function: &SwayFunction, ast: &SwayAst) -> bool {
        // Only check public functions or functions called by public functions
        if matches!(function.visibility, crate::parser::FunctionVisibility::Public) {
            return true;
        }
        
        // Check if this function is called by any public function
        for other_func in &ast.functions {
            if matches!(other_func.visibility, crate::parser::FunctionVisibility::Public) {
                // Simple check if function name appears in public function
                if other_func.content.contains(&function.name) {
                    return true;
                }
            }
        }
        
        false
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