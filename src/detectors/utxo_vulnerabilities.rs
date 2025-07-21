use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct UtxoVulnerabilitiesDetector;

impl UtxoVulnerabilitiesDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_utxo_vulnerabilities(&self, function: &SwayFunction, file: &SwayFile, _ast: &SwayAst) -> Option<Finding> {
        let mut visitor = UtxoVulnerabilitiesVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "utxo_vulnerabilities",
                Severity::High,
                Category::Security,
                0.9,
                &format!("UTXO Vulnerability Detected - {} (line {}, col {})", function.name, line_number, column),
                &finding.message,
                &file.path,
                line_number,
                line_number,
                &function.content,
                &finding.suggestion,
            ))
        } else {
            None
        }
    }
}

/// Advanced AST Visitor for UTXO Vulnerabilities Detection
struct UtxoVulnerabilitiesVisitor {
    findings: Vec<AstFinding>,
    utxo_operations: Vec<(String, usize)>, // (operation, line_number)
    coin_operations: Vec<(String, usize)>,
    has_double_spend_risk: bool,
    has_invalid_utxo_usage: bool,
    has_missing_validation: bool,
    has_unsafe_coin_operations: bool,
    utxo_variables: Vec<String>,
    coin_variables: Vec<String>,
    input_operations: Vec<String>,
    output_operations: Vec<String>,
}

impl UtxoVulnerabilitiesVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            utxo_operations: Vec::new(),
            coin_operations: Vec::new(),
            has_double_spend_risk: false,
            has_invalid_utxo_usage: false,
            has_missing_validation: false,
            has_unsafe_coin_operations: false,
            utxo_variables: Vec::new(),
            coin_variables: Vec::new(),
            input_operations: Vec::new(),
            output_operations: Vec::new(),
        }
    }
}

impl AstVisitor for UtxoVulnerabilitiesVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.utxo_operations.clear();
        self.coin_operations.clear();
        self.has_double_spend_risk = false;
        self.has_invalid_utxo_usage = false;
        self.has_missing_validation = false;
        self.has_unsafe_coin_operations = false;
        self.utxo_variables.clear();
        self.coin_variables.clear();
        self.input_operations.clear();
        self.output_operations.clear();
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Analyze UTXO vulnerability patterns
        self.analyze_utxo_vulnerability_patterns(function);
        
        self.findings.clone()
    }

    fn visit_statement(&mut self, statement: &SwayStatement) -> Vec<AstFinding> {
        self.visit_statement_kind(&statement.kind);
        self.findings.clone()
    }

    fn visit_expression(&mut self, expression: &SwayExpression) -> Vec<AstFinding> {
        self.visit_expression_kind(&expression.kind);
        self.findings.clone()
    }

    fn visit_statement_kind(&mut self, kind: &StatementKind) -> Vec<AstFinding> {
        match kind {
            StatementKind::Expression(expr) => {
                self.visit_expression(expr);
            }
            StatementKind::Let(let_stmt) => {
                // Check for UTXO-related variable assignments
                if self.is_utxo_related_variable(&let_stmt.pattern) {
                    self.utxo_variables.push(self.pattern_to_string(&let_stmt.pattern));
                }
                if self.is_coin_related_variable(&let_stmt.pattern) {
                    self.coin_variables.push(self.pattern_to_string(&let_stmt.pattern));
                }
                self.visit_expression(&let_stmt.value);
            }
            StatementKind::Return(expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr);
                }
            }
            StatementKind::If(if_stmt) => {
                // Check for UTXO validation in conditions
                self.check_utxo_validation_in_condition(&if_stmt.condition);
                self.visit_expression(&if_stmt.condition);
                
                for stmt in &if_stmt.then_block {
                    self.visit_statement(stmt);
                }
                
                if let Some(else_block) = &if_stmt.else_block {
                    for stmt in else_block {
                        self.visit_statement(stmt);
                    }
                }
            }
            StatementKind::While(while_stmt) => {
                self.visit_expression(&while_stmt.condition);
                
                for stmt in &while_stmt.body {
                    self.visit_statement(stmt);
                }
            }
            StatementKind::For(for_stmt) => {
                self.visit_expression(&for_stmt.iterator);
                
                for stmt in &for_stmt.body {
                    self.visit_statement(stmt);
                }
            }
            StatementKind::Match(match_stmt) => {
                self.visit_expression(&match_stmt.expression);
                
                for arm in &match_stmt.arms {
                    if let Some(guard) = &arm.guard {
                        self.visit_expression(guard);
                    }
                    
                    for stmt in &arm.body {
                        self.visit_statement(stmt);
                    }
                }
            }
            StatementKind::Block(statements) => {
                for stmt in statements {
                    self.visit_statement(stmt);
                }
            }
            StatementKind::Storage(storage_stmt) => {
                // Check for UTXO storage operations
                if self.is_utxo_storage_operation(storage_stmt) {
                    self.utxo_operations.push((
                        format!("storage.{}", storage_stmt.field),
                        0 // Use default line number since StorageStatement doesn't have span
                    ));
                }
            }
            StatementKind::Require(require_stmt) => {
                self.visit_expression(&require_stmt.condition);
            }
            StatementKind::Assert(assert_stmt) => {
                self.visit_expression(&assert_stmt.condition);
            }
            StatementKind::Break | StatementKind::Continue => {}
        }
        
        self.findings.clone()
    }

    fn visit_expression_kind(&mut self, kind: &ExpressionKind) -> Vec<AstFinding> {
        match kind {
            ExpressionKind::Literal(_) => {}
            ExpressionKind::Variable(var) => {
                // Check for UTXO-related variables
                if self.is_utxo_variable(var) {
                    self.utxo_variables.push(var.clone());
                }
                if self.is_coin_variable(var) {
                    self.coin_variables.push(var.clone());
                }
            }
            ExpressionKind::FunctionCall(func_call) => {
                // Check for UTXO function calls
                if self.is_utxo_function_call(&func_call.function) {
                    self.utxo_operations.push((
                        format!("{}(...)", func_call.function),
                        func_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                    ));
                }
                
                // Check for coin function calls
                if self.is_coin_function_call(&func_call.function) {
                    self.coin_operations.push((
                        format!("{}(...)", func_call.function),
                        func_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                    ));
                }
                
                // Check for input/output operations
                if self.is_input_operation(&func_call.function) {
                    self.input_operations.push(func_call.function.clone());
                }
                if self.is_output_operation(&func_call.function) {
                    self.output_operations.push(func_call.function.clone());
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for UTXO method calls
                if self.is_utxo_method_call(&method_call.method) {
                    self.utxo_operations.push((
                        format!("{}.{}()", "receiver", method_call.method),
                        method_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                    ));
                }
                
                // Check for coin method calls
                if self.is_coin_method_call(&method_call.method) {
                    self.coin_operations.push((
                        format!("{}.{}()", "receiver", method_call.method),
                        method_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                    ));
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for UTXO manipulation in binary operations
                self.check_utxo_manipulation_in_binary_operation(binary_expr);
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
                self.check_utxo_validation_in_condition(&if_expr.condition);
                self.visit_expression(&if_expr.condition);
                self.visit_expression(&if_expr.then_expr);
                
                if let Some(else_expr) = &if_expr.else_expr {
                    self.visit_expression(else_expr);
                }
            }
            ExpressionKind::Match(match_expr) => {
                self.visit_expression(&match_expr.expression);
                
                for arm in &match_expr.arms {
                    if let Some(guard) = &arm.guard {
                        self.visit_expression(guard);
                    }
                    
                    for stmt in &arm.body {
                        self.visit_statement(stmt);
                    }
                }
            }
            ExpressionKind::Block(statements) => {
                for stmt in statements {
                    self.visit_statement(stmt);
                }
            }
            ExpressionKind::Array(expressions) => {
                for expr in expressions {
                    self.visit_expression(expr);
                }
            }
            ExpressionKind::Tuple(expressions) => {
                for expr in expressions {
                    self.visit_expression(expr);
                }
            }
            ExpressionKind::Struct(struct_expr) => {
                for field in &struct_expr.fields {
                    self.visit_expression(&field.value);
                }
            }
            ExpressionKind::Index(index_expr) => {
                self.visit_expression(&index_expr.array);
                self.visit_expression(&index_expr.index);
            }
            ExpressionKind::Field(field_expr) => {
                // Check for UTXO field access
                if self.is_utxo_field_access(&field_expr.field) {
                    self.has_invalid_utxo_usage = true;
                }
                self.visit_expression(&field_expr.receiver);
            }
            ExpressionKind::Parenthesized(expr) => {
                self.visit_expression(expr);
            }
        }
        
        self.findings.clone()
    }
}

impl UtxoVulnerabilitiesVisitor {
    /// Check for UTXO validation patterns in conditional expressions
    fn check_utxo_validation_in_condition(&mut self, condition: &SwayExpression) {
        // Check if condition involves UTXO validation
        if self.is_utxo_validation_condition(condition) {
            self.has_missing_validation = false; // Found validation
        } else if self.has_utxo_operations() && !self.has_validation_checks() {
            self.has_missing_validation = true;
        }
        
        self.visit_expression(condition);
    }
    
    /// Check for UTXO manipulation in binary operations
    fn check_utxo_manipulation_in_binary_operation(&mut self, binary_expr: &crate::parser::BinaryExpression) {
        // Check for UTXO manipulation patterns
        if self.is_utxo_manipulation_operation(binary_expr) {
            self.utxo_operations.push((
                format!("{} {} {}", 
                    self.expression_to_string(&binary_expr.left),
                    binary_expr.operator,
                    self.expression_to_string(&binary_expr.right)
                ),
                binary_expr.left.span.start
            ));
        }
    }
    
    /// Check if a pattern is UTXO-related
    fn is_utxo_related_variable(&self, pattern: &crate::parser::SwayPattern) -> bool {
        match &pattern.kind {
            crate::parser::PatternKind::Variable(var) => {
                self.is_utxo_variable(var)
            }
            _ => false,
        }
    }
    
    /// Check if a pattern is coin-related
    fn is_coin_related_variable(&self, pattern: &crate::parser::SwayPattern) -> bool {
        match &pattern.kind {
            crate::parser::PatternKind::Variable(var) => {
                self.is_coin_variable(var)
            }
            _ => false,
        }
    }
    
    /// Check if a variable is UTXO-related
    fn is_utxo_variable(&self, var: &str) -> bool {
        matches!(var, 
            "utxo" | "input" | "output" | "tx_input" | "tx_output" | "coin_input" | "coin_output" |
            "spent_utxo" | "unspent_utxo" | "utxo_id" | "utxo_hash" | "utxo_data"
        )
    }
    
    /// Check if a variable is coin-related
    fn is_coin_variable(&self, var: &str) -> bool {
        matches!(var, 
            "coin" | "coins" | "coin_amount" | "coin_id" | "coin_hash" | "coin_data" |
            "base_asset" | "asset_id" | "asset_amount"
        )
    }
    
    /// Check if a storage operation is UTXO-related
    fn is_utxo_storage_operation(&self, storage_stmt: &crate::parser::StorageStatement) -> bool {
        matches!(storage_stmt.field.as_str(), 
            "utxos" | "spent_utxos" | "unspent_utxos" | "utxo_set" | "coin_set" | "input_set" | "output_set"
        )
    }
    
    /// Check if a function call is a UTXO function
    fn is_utxo_function_call(&self, function: &str) -> bool {
        matches!(function, 
            "spend_utxo" | "create_utxo" | "validate_utxo" | "get_utxo" | "find_utxo" |
            "spend_input" | "create_output" | "validate_input" | "validate_output"
        )
    }
    
    /// Check if a function call is a coin function
    fn is_coin_function_call(&self, function: &str) -> bool {
        matches!(function, 
            "mint_coin" | "burn_coin" | "transfer_coin" | "get_coin" | "validate_coin" |
            "mint_to" | "burn_from" | "force_transfer_to_contract"
        )
    }
    
    /// Check if a method call is a UTXO method
    fn is_utxo_method_call(&self, method: &str) -> bool {
        matches!(method, 
            "spend" | "create" | "validate" | "get" | "find" | "is_spent" | "is_unspent"
        )
    }
    
    /// Check if a method call is a coin method
    fn is_coin_method_call(&self, method: &str) -> bool {
        matches!(method, 
            "mint" | "burn" | "transfer" | "get" | "validate" | "amount" | "asset_id"
        )
    }
    
    /// Check if a function is an input operation
    fn is_input_operation(&self, function: &str) -> bool {
        matches!(function, 
            "spend_input" | "validate_input" | "get_input" | "find_input" | "consume_input"
        )
    }
    
    /// Check if a function is an output operation
    fn is_output_operation(&self, function: &str) -> bool {
        matches!(function, 
            "create_output" | "validate_output" | "get_output" | "find_output" | "generate_output"
        )
    }
    
    /// Check if a field access is UTXO-related
    fn is_utxo_field_access(&self, field: &str) -> bool {
        matches!(field, 
            "utxo" | "input" | "output" | "spent" | "unspent" | "amount" | "asset_id"
        )
    }
    
    /// Check if a condition involves UTXO validation
    fn is_utxo_validation_condition(&self, condition: &SwayExpression) -> bool {
        // Check for UTXO validation patterns in conditions
        match &condition.kind {
            ExpressionKind::Binary(binary_expr) => {
                let left_str = self.expression_to_string(&binary_expr.left);
                let right_str = self.expression_to_string(&binary_expr.right);
                
                // Check for validation patterns
                (self.is_utxo_variable(&left_str) || self.is_utxo_variable(&right_str)) &&
                matches!(binary_expr.operator.as_str(), "==" | "!=" | ">" | "<" | ">=" | "<=")
            }
            ExpressionKind::FunctionCall(func_call) => {
                matches!(func_call.function.as_str(), 
                    "validate_utxo" | "validate_input" | "validate_output" | "is_spent" | "is_unspent"
                )
            }
            _ => false,
        }
    }
    
    /// Check if a binary operation is UTXO manipulation
    fn is_utxo_manipulation_operation(&self, binary_expr: &crate::parser::BinaryExpression) -> bool {
        let left_str = self.expression_to_string(&binary_expr.left);
        let right_str = self.expression_to_string(&binary_expr.right);
        
        // Check for UTXO manipulation patterns
        (self.is_utxo_variable(&left_str) || self.is_utxo_variable(&right_str)) &&
        matches!(binary_expr.operator.as_str(), "+" | "-" | "*" | "/")
    }
    
    /// Convert pattern to string
    fn pattern_to_string(&self, pattern: &crate::parser::SwayPattern) -> String {
        match &pattern.kind {
            crate::parser::PatternKind::Variable(var) => var.clone(),
            _ => "pattern".to_string(),
        }
    }
    
    /// Convert expression to string for reporting
    fn expression_to_string(&self, expr: &SwayExpression) -> String {
        match &expr.kind {
            ExpressionKind::Literal(literal) => literal.value.clone(),
            ExpressionKind::Variable(var) => var.clone(),
            ExpressionKind::FunctionCall(func_call) => format!("{}(...)", func_call.function),
            ExpressionKind::MethodCall(method_call) => format!("{}.{}()", "receiver", method_call.method),
            _ => "expression".to_string(),
        }
    }
    
    /// Analyze UTXO vulnerability patterns
    fn analyze_utxo_vulnerability_patterns(&mut self, function: &SwayFunction) {
        // Check for double spend risk
        if self.has_input_operations() && !self.has_validation_checks() {
            self.has_double_spend_risk = true;
        }
        
        // Check for invalid UTXO usage
        if self.has_utxo_operations() && !self.has_proper_validation() {
            self.has_invalid_utxo_usage = true;
        }
        
        // Check for unsafe coin operations
        if !self.coin_operations.is_empty() && !self.has_coin_validation() {
            self.has_unsafe_coin_operations = true;
        }
        
        // Generate findings based on detected patterns
        if self.has_double_spend_risk {
            self.findings.push(AstFinding::new(
                "utxo_vulnerabilities",
                "High",
                "Potential double spend vulnerability detected. Input operations without proper validation.",
                (function.span.start, function.span.end),
                format!("Input operations: {}", self.input_operations.join(", ")),
                "Implement proper UTXO validation and double spend protection mechanisms."
            ));
        }
        
        if self.has_invalid_utxo_usage {
            self.findings.push(AstFinding::new(
                "utxo_vulnerabilities",
                "High",
                "Invalid UTXO usage detected. UTXO operations without proper validation.",
                (function.span.start, function.span.end),
                format!("UTXO operations: {}", 
                    self.utxo_operations.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Implement proper UTXO validation and ensure UTXOs are spent correctly."
            ));
        }
        
        if self.has_unsafe_coin_operations {
            self.findings.push(AstFinding::new(
                "utxo_vulnerabilities",
                "High",
                "Unsafe coin operations detected. Coin operations without proper validation.",
                (function.span.start, function.span.end),
                format!("Coin operations: {}", 
                    self.coin_operations.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Implement proper coin validation and ensure safe coin operations."
            ));
        }
        
        if self.has_missing_validation {
            self.findings.push(AstFinding::new(
                "utxo_vulnerabilities",
                "High",
                "Missing UTXO validation detected. UTXO operations without proper checks.",
                (function.span.start, function.span.end),
                format!("UTXO variables: {}", self.utxo_variables.join(", ")),
                "Implement comprehensive UTXO validation including existence, ownership, and double spend checks."
            ));
        }
    }
    
    /// Check if input operations are present
    fn has_input_operations(&self) -> bool {
        !self.input_operations.is_empty()
    }
    
    /// Check if validation checks are present
    fn has_validation_checks(&self) -> bool {
        // Check for validation patterns
        self.utxo_variables.iter().any(|var| 
            var.contains("validate") || var.contains("check") || var.contains("verify")
        )
    }
    
    /// Check if proper validation is present
    fn has_proper_validation(&self) -> bool {
        // Check for comprehensive validation
        self.has_validation_checks() && self.has_ownership_checks()
    }
    
    /// Check if ownership checks are present
    fn has_ownership_checks(&self) -> bool {
        // Check for ownership validation patterns
        self.utxo_variables.iter().any(|var| 
            var.contains("owner") || var.contains("sender") || var.contains("signer")
        )
    }
    
    /// Check if coin validation is present
    fn has_coin_validation(&self) -> bool {
        // Check for coin validation patterns
        self.coin_variables.iter().any(|var| 
            var.contains("validate") || var.contains("check") || var.contains("verify")
        )
    }
    
    /// Check if UTXO operations are present
    fn has_utxo_operations(&self) -> bool {
        !self.utxo_operations.is_empty()
    }
}

impl Detector for UtxoVulnerabilitiesDetector {
    fn name(&self) -> &'static str {
        "utxo_vulnerabilities"
    }
    fn description(&self) -> &'static str {
        "Detects UTXO vulnerabilities using advanced AST-based semantic analysis."
    }
    fn category(&self) -> Category {
        Category::Security
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_utxo_vulnerabilities(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 