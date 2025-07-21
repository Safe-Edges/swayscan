use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct StrictEqualityDetector;

impl StrictEqualityDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_strict_equality(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = StrictEqualityVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "strict_equality",
                Severity::Medium,
                Category::LogicErrors,
                0.8,
                &format!("Strict Equality Issue Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Strict Equality Detection
struct StrictEqualityVisitor {
    findings: Vec<AstFinding>,
    strict_equality_comparisons: Vec<(String, usize)>, // (comparison, line_number)
    float_comparisons: Vec<(String, usize)>,
    address_comparisons: Vec<(String, usize)>,
    has_floating_point_operations: bool,
    has_address_operations: bool,
}

impl StrictEqualityVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            strict_equality_comparisons: Vec::new(),
            float_comparisons: Vec::new(),
            address_comparisons: Vec::new(),
            has_floating_point_operations: false,
            has_address_operations: false,
        }
    }
}

impl AstVisitor for StrictEqualityVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.strict_equality_comparisons.clear();
        self.float_comparisons.clear();
        self.address_comparisons.clear();
        self.has_floating_point_operations = false;
        self.has_address_operations = false;
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Analyze strict equality patterns
        self.analyze_strict_equality_patterns(function);
        
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
                self.visit_expression(&let_stmt.value);
            }
            StatementKind::Return(expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr);
                }
            }
            StatementKind::If(if_stmt) => {
                // Check for strict equality in if conditions
                self.check_strict_equality_in_condition(&if_stmt.condition);
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
            StatementKind::Storage(_) => {
                // Handle storage operations
            }
            StatementKind::Require(require_stmt) => {
                self.check_strict_equality_in_condition(&require_stmt.condition);
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
            ExpressionKind::Literal(literal) => {
                // Check for float literals
                if self.is_float_literal(&literal.value) {
                    self.has_floating_point_operations = true;
                }
            }
            ExpressionKind::Variable(_) => {}
            ExpressionKind::FunctionCall(func_call) => {
                // Check for address-related operations
                if self.is_address_operation(&func_call.function) {
                    self.has_address_operations = true;
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for address-related operations
                if self.is_address_operation(&method_call.method) {
                    self.has_address_operations = true;
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for strict equality comparisons
                self.check_strict_equality_comparison(binary_expr);
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
                self.check_strict_equality_in_condition(&if_expr.condition);
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
                self.visit_expression(&field_expr.receiver);
            }
            ExpressionKind::Parenthesized(expr) => {
                self.visit_expression(expr);
            }
        }
        
        self.findings.clone()
    }
}

impl StrictEqualityVisitor {
    /// Check for strict equality comparisons
    fn check_strict_equality_comparison(&mut self, binary_expr: &crate::parser::BinaryExpression) {
        if binary_expr.operator == "==" || binary_expr.operator == "!=" {
            let left_is_float = self.is_float_expression(&binary_expr.left);
            let right_is_float = self.is_float_expression(&binary_expr.right);
            let left_is_address = self.is_address_expression(&binary_expr.left);
            let right_is_address = self.is_address_expression(&binary_expr.right);
            
            if left_is_float || right_is_float {
                self.float_comparisons.push((
                    format!("{} {} {}", 
                        self.expression_to_string(&binary_expr.left),
                        binary_expr.operator,
                        self.expression_to_string(&binary_expr.right)
                    ),
                    binary_expr.left.span.start
                ));
            }
            
            if left_is_address || right_is_address {
                self.address_comparisons.push((
                    format!("{} {} {}", 
                        self.expression_to_string(&binary_expr.left),
                        binary_expr.operator,
                        self.expression_to_string(&binary_expr.right)
                    ),
                    binary_expr.left.span.start
                ));
            }
            
            // Track all strict equality comparisons
            self.strict_equality_comparisons.push((
                format!("{} {} {}", 
                    self.expression_to_string(&binary_expr.left),
                    binary_expr.operator,
                    self.expression_to_string(&binary_expr.right)
                ),
                binary_expr.left.span.start
            ));
        }
    }
    
    /// Check for strict equality in conditional expressions
    fn check_strict_equality_in_condition(&mut self, condition: &SwayExpression) {
        // This will be called by the visitor pattern when visiting if/require conditions
        // The actual checking is done in check_strict_equality_comparison
        self.visit_expression(condition);
    }
    
    /// Check if a literal is a float
    fn is_float_literal(&self, value: &str) -> bool {
        value.contains('.') && value.parse::<f64>().is_ok()
    }
    
    /// Check if an expression is a float
    fn is_float_expression(&self, expr: &SwayExpression) -> bool {
        match &expr.kind {
            ExpressionKind::Literal(literal) => self.is_float_literal(&literal.value),
            ExpressionKind::Variable(var) => var.contains("float") || var.contains("price") || var.contains("rate"),
            ExpressionKind::FunctionCall(func_call) => {
                matches!(func_call.function.as_str(), 
                    "calculate_price" | "calculate_rate" | "calculate_fee" | "get_balance" | "get_amount"
                )
            }
            _ => false,
        }
    }
    
    /// Check if an expression is an address
    fn is_address_expression(&self, expr: &SwayExpression) -> bool {
        match &expr.kind {
            ExpressionKind::Literal(literal) => {
                literal.value.starts_with("0x") && literal.value.len() == 42
            }
            ExpressionKind::Variable(var) => {
                var.contains("address") || var.contains("sender") || var.contains("recipient") || 
                var.contains("owner") || var.contains("admin")
            }
            ExpressionKind::FunctionCall(func_call) => {
                matches!(func_call.function.as_str(), 
                    "msg_sender" | "get_sender" | "get_recipient" | "get_owner"
                )
            }
            _ => false,
        }
    }
    
    /// Check if an operation is address-related
    fn is_address_operation(&self, operation: &str) -> bool {
        matches!(operation, 
            "msg_sender" | "get_sender" | "get_recipient" | "get_owner" | "get_admin" |
            "transfer" | "send" | "call"
        )
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
    
    /// Analyze strict equality patterns
    fn analyze_strict_equality_patterns(&mut self, function: &SwayFunction) {
        // Check for problematic float comparisons
        if !self.float_comparisons.is_empty() {
            self.findings.push(AstFinding::new(
                "strict_equality",
                "Medium",
                "Strict equality comparison with floating-point values detected. This may cause precision issues.",
                (function.span.start, function.span.end),
                format!("Float comparisons: {}", 
                    self.float_comparisons.iter().map(|(comp, _)| comp.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Use approximate comparison with tolerance for floating-point values."
            ));
        }
        
        // Check for problematic address comparisons
        if !self.address_comparisons.is_empty() {
            self.findings.push(AstFinding::new(
                "strict_equality",
                "Medium",
                "Strict equality comparison with address values detected. Consider using safe address comparison.",
                (function.span.start, function.span.end),
                format!("Address comparisons: {}", 
                    self.address_comparisons.iter().map(|(comp, _)| comp.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Use safe address comparison methods or consider using address libraries."
            ));
        }
        
        // Check for general strict equality issues
        if !self.strict_equality_comparisons.is_empty() && (self.has_floating_point_operations || self.has_address_operations) {
            self.findings.push(AstFinding::new(
                "strict_equality",
                "Medium",
                "Strict equality comparisons detected in context with floating-point or address operations.",
                (function.span.start, function.span.end),
                format!("Strict equality comparisons: {}", 
                    self.strict_equality_comparisons.iter().map(|(comp, _)| comp.clone()).collect::<Vec<_>>().join(", ")
                ),
                "Consider using appropriate comparison methods for the data types involved."
            ));
        }
    }
}

impl Detector for StrictEqualityDetector {
    fn name(&self) -> &'static str {
        "strict_equality"
    }
    fn description(&self) -> &'static str {
        "Detects problematic strict equality comparisons using advanced AST-based semantic analysis."
    }
    fn category(&self) -> Category {
        Category::LogicErrors
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_strict_equality(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}