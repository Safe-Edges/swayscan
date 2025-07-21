use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct PriceOracleManipulationDetector;

impl PriceOracleManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_price_oracle_manipulation(&self, function: &SwayFunction, file: &SwayFile, _ast: &SwayAst) -> Option<Finding> {
        let mut visitor = PriceOracleManipulationVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "price_oracle_manipulation",
                Severity::High,
                Category::Security,
                0.9,
                &format!("Price Oracle Manipulation Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Price Oracle Manipulation Detection
struct PriceOracleManipulationVisitor {
    findings: Vec<AstFinding>,
    oracle_sources: Vec<String>,
    price_operations: Vec<(String, usize)>, // (operation, line_number)
    has_single_oracle: bool,
    has_no_staleness_check: bool,
    has_no_deviation_check: bool,
    has_direct_price_usage: bool,
    has_manipulation_risk: bool,
    price_variables: Vec<String>,
    oracle_calls: Vec<String>,
}

impl PriceOracleManipulationVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            oracle_sources: Vec::new(),
            price_operations: Vec::new(),
            has_single_oracle: false,
            has_no_staleness_check: false,
            has_no_deviation_check: false,
            has_direct_price_usage: false,
            has_manipulation_risk: false,
            price_variables: Vec::new(),
            oracle_calls: Vec::new(),
        }
    }
}

impl AstVisitor for PriceOracleManipulationVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.oracle_sources.clear();
        self.price_operations.clear();
        self.has_single_oracle = false;
        self.has_no_staleness_check = false;
        self.has_no_deviation_check = false;
        self.has_direct_price_usage = false;
        self.has_manipulation_risk = false;
        self.price_variables.clear();
        self.oracle_calls.clear();
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Analyze price oracle manipulation patterns
        self.analyze_price_oracle_patterns(function);
        
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
                // Check for price-related variable assignments
                if self.is_price_related_variable(&let_stmt.pattern) {
                    self.price_variables.push(self.pattern_to_string(&let_stmt.pattern));
                }
                self.visit_expression(&let_stmt.value);
            }
            StatementKind::Return(expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr);
                }
            }
            StatementKind::If(if_stmt) => {
                // Check for price manipulation in conditions
                self.check_price_manipulation_in_condition(&if_stmt.condition);
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
                // Check for price storage operations
                if self.is_price_storage_operation(storage_stmt) {
                    self.price_operations.push((
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
                // Check for price-related variables
                if self.is_price_variable(var) {
                    self.price_variables.push(var.clone());
                }
            }
            ExpressionKind::FunctionCall(func_call) => {
                // Check for oracle function calls
                if self.is_oracle_call(&func_call.function) {
                    self.oracle_calls.push(func_call.function.clone());
                    self.oracle_sources.push(func_call.function.clone());
                }
                
                // Check for price manipulation functions
                if self.is_price_manipulation_function(&func_call.function) {
                    self.has_manipulation_risk = true;
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for oracle method calls
                if self.is_oracle_method_call(&method_call.method) {
                    self.oracle_calls.push(format!("{}.{}", "receiver", method_call.method));
                    self.oracle_sources.push(method_call.method.clone());
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for price manipulation in binary operations
                self.check_price_manipulation_in_binary_operation(binary_expr);
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
                self.check_price_manipulation_in_condition(&if_expr.condition);
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
                // Check for price field access
                if self.is_price_field_access(&field_expr.field) {
                    self.has_direct_price_usage = true;
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

impl PriceOracleManipulationVisitor {
    /// Check for price manipulation patterns in conditional expressions
    fn check_price_manipulation_in_condition(&mut self, condition: &SwayExpression) {
        // Check if condition involves price manipulation
        if self.is_price_manipulation_condition(condition) {
            self.has_manipulation_risk = true;
        }
        
        self.visit_expression(condition);
    }
    
    /// Check for price manipulation in binary operations
    fn check_price_manipulation_in_binary_operation(&mut self, binary_expr: &crate::parser::BinaryExpression) {
        // Check for price manipulation patterns
        if self.is_price_manipulation_operation(binary_expr) {
            self.price_operations.push((
                format!("{} {} {}", 
                    self.expression_to_string(&binary_expr.left),
                    binary_expr.operator,
                    self.expression_to_string(&binary_expr.right)
                ),
                binary_expr.left.span.start
            ));
        }
    }
    
    /// Check if a pattern is price-related
    fn is_price_related_variable(&self, pattern: &crate::parser::SwayPattern) -> bool {
        match &pattern.kind {
            crate::parser::PatternKind::Variable(var) => {
                self.is_price_variable(var)
            }
            _ => false,
        }
    }
    
    /// Check if a variable is price-related
    fn is_price_variable(&self, var: &str) -> bool {
        matches!(var, 
            "price" | "oracle_price" | "asset_price" | "token_price" | "usd_price" |
            "oracle" | "feed" | "price_feed" | "price_data" | "price_info"
        )
    }
    
    /// Check if a storage operation is price-related
    fn is_price_storage_operation(&self, storage_stmt: &crate::parser::StorageStatement) -> bool {
        matches!(storage_stmt.field.as_str(), 
            "oracle_prices" | "price_data" | "price_feeds" | "asset_prices" | "token_prices"
        )
    }
    
    /// Check if a function call is an oracle call
    fn is_oracle_call(&self, function: &str) -> bool {
        matches!(function, 
            "get_price" | "fetch_price" | "oracle_price" | "price_feed" | "chainlink_price" |
            "pyth_price" | "band_price" | "price_oracle" | "get_oracle_price"
        )
    }
    
    /// Check if a method call is an oracle method
    fn is_oracle_method_call(&self, method: &str) -> bool {
        matches!(method, 
            "price" | "latest_price" | "get_price" | "fetch_price" | "oracle_data"
        )
    }
    
    /// Check if a function is a price manipulation function
    fn is_price_manipulation_function(&self, function: &str) -> bool {
        matches!(function, 
            "update_price" | "set_price" | "modify_price" | "adjust_price" | "manipulate_price"
        )
    }
    
    /// Check if a field access is price-related
    fn is_price_field_access(&self, field: &str) -> bool {
        matches!(field, 
            "price" | "oracle_price" | "asset_price" | "token_price" | "usd_price"
        )
    }
    
    /// Check if a condition involves price manipulation
    fn is_price_manipulation_condition(&self, condition: &SwayExpression) -> bool {
        // Check for price manipulation patterns in conditions
        match &condition.kind {
            ExpressionKind::Binary(binary_expr) => {
                let left_str = self.expression_to_string(&binary_expr.left);
                let right_str = self.expression_to_string(&binary_expr.right);
                
                // Check for price comparison patterns
                (self.is_price_variable(&left_str) || self.is_price_variable(&right_str)) &&
                matches!(binary_expr.operator.as_str(), ">" | "<" | ">=" | "<=" | "==" | "!=")
            }
            _ => false,
        }
    }
    
    /// Check if a binary operation is price manipulation
    fn is_price_manipulation_operation(&self, binary_expr: &crate::parser::BinaryExpression) -> bool {
        let left_str = self.expression_to_string(&binary_expr.left);
        let right_str = self.expression_to_string(&binary_expr.right);
        
        // Check for price manipulation patterns
        (self.is_price_variable(&left_str) || self.is_price_variable(&right_str)) &&
        matches!(binary_expr.operator.as_str(), "*" | "/" | "+" | "-")
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
    
    /// Analyze price oracle manipulation patterns
    fn analyze_price_oracle_patterns(&mut self, function: &SwayFunction) {
        // Check for single oracle source
        if self.oracle_sources.len() == 1 {
            self.has_single_oracle = true;
        }
        
        // Check for direct price usage without validation
        if self.has_direct_price_usage && !self.has_staleness_check() {
            self.has_no_staleness_check = true;
        }
        
        // Check for missing deviation checks
        if self.has_price_operations() && !self.has_deviation_check() {
            self.has_no_deviation_check = true;
        }
        
        // Generate findings based on detected patterns
        if self.has_single_oracle {
            self.findings.push(AstFinding::new(
                "price_oracle_manipulation",
                "High",
                "Single oracle source detected. Vulnerable to price manipulation attacks.",
                (function.span.start, function.span.end),
                format!("Oracle sources: {}", self.oracle_sources.join(", ")),
                "Use multiple oracle sources and implement deviation checks to prevent price manipulation."
            ));
        }
        
        if self.has_no_staleness_check {
            self.findings.push(AstFinding::new(
                "price_oracle_manipulation",
                "High",
                "Price oracle usage without staleness check detected.",
                (function.span.start, function.span.end),
                format!("Price operations: {}", 
                    self.price_operations.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Implement staleness checks and use recent price data only."
            ));
        }
        
        if self.has_no_deviation_check {
            self.findings.push(AstFinding::new(
                "price_oracle_manipulation",
                "High",
                "Price operations without deviation checks detected.",
                (function.span.start, function.span.end),
                format!("Price variables: {}", self.price_variables.join(", ")),
                "Implement price deviation checks and use multiple oracle sources."
            ));
        }
        
        if self.has_manipulation_risk {
            self.findings.push(AstFinding::new(
                "price_oracle_manipulation",
                "High",
                "Potential price manipulation risk detected in function logic.",
                (function.span.start, function.span.end),
                format!("Oracle calls: {}", self.oracle_calls.join(", ")),
                "Implement proper price validation, use multiple sources, and add manipulation protection."
            ));
        }
    }
    
    /// Check if staleness check is present
    fn has_staleness_check(&self) -> bool {
        // Check for staleness check patterns
        self.oracle_calls.iter().any(|call| 
            call.contains("staleness") || call.contains("timestamp") || call.contains("recent")
        )
    }
    
    /// Check if deviation check is present
    fn has_deviation_check(&self) -> bool {
        // Check for deviation check patterns
        self.price_operations.iter().any(|(op, _)| 
            op.contains("deviation") || op.contains("threshold") || op.contains("bound")
        )
    }
    
    /// Check if price operations are present
    fn has_price_operations(&self) -> bool {
        !self.price_operations.is_empty()
    }
}

impl Detector for PriceOracleManipulationDetector {
    fn name(&self) -> &'static str {
        "price_oracle_manipulation"
    }
    fn description(&self) -> &'static str {
        "Detects price oracle manipulation vulnerabilities using advanced AST-based semantic analysis."
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
                if let Some(finding) = self.analyze_function_price_oracle_manipulation(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 