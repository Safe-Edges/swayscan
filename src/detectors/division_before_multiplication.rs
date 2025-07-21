
use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct DivisionBeforeMultiplicationDetector;

impl DivisionBeforeMultiplicationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_division_before_multiplication(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = DivisionBeforeMultiplicationVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "division_before_multiplication",
                Severity::Medium,
                Category::LogicErrors,
                0.8,
                &format!("Division Before Multiplication Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Division Before Multiplication Detection
struct DivisionBeforeMultiplicationVisitor {
    findings: Vec<AstFinding>,
    division_operations: Vec<(String, usize)>, // (operation, line_number)
    multiplication_operations: Vec<(String, usize)>,
    financial_operations: Vec<String>,
    has_precision_loss: bool,
}

impl DivisionBeforeMultiplicationVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            division_operations: Vec::new(),
            multiplication_operations: Vec::new(),
            financial_operations: Vec::new(),
            has_precision_loss: false,
        }
    }
}

impl AstVisitor for DivisionBeforeMultiplicationVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.division_operations.clear();
        self.multiplication_operations.clear();
        self.financial_operations.clear();
        self.has_precision_loss = false;
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Analyze division before multiplication patterns
        self.analyze_division_before_multiplication_patterns(function);
        
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
            ExpressionKind::Variable(_) => {}
            ExpressionKind::FunctionCall(func_call) => {
                // Check for financial operations
                if self.is_financial_operation(&func_call.function) {
                    self.financial_operations.push(func_call.function.clone());
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for financial operations
                if self.is_financial_operation(&method_call.method) {
                    self.financial_operations.push(method_call.method.clone());
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for division and multiplication operations
                self.check_arithmetic_operation(binary_expr);
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
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

impl DivisionBeforeMultiplicationVisitor {
    /// Check for arithmetic operations that could cause precision loss
    fn check_arithmetic_operation(&mut self, binary_expr: &crate::parser::BinaryExpression) {
        match binary_expr.operator.as_str() {
            "/" => {
                // Track division operations
                self.division_operations.push((
                    format!("{} / {}", 
                        self.expression_to_string(&binary_expr.left),
                        self.expression_to_string(&binary_expr.right)
                    ),
                    binary_expr.left.span.start
                ));
            }
            "*" => {
                // Track multiplication operations
                self.multiplication_operations.push((
                    format!("{} * {}", 
                        self.expression_to_string(&binary_expr.left),
                        self.expression_to_string(&binary_expr.right)
                    ),
                    binary_expr.left.span.start
                ));
            }
            _ => {}
        }
    }
    
    /// Check if an operation is financial-related
    fn is_financial_operation(&self, operation: &str) -> bool {
        matches!(operation, 
            "transfer" | "mint" | "burn" | "withdraw" | "deposit" | 
            "calculate_interest" | "calculate_fee" | "calculate_reward" |
            "price" | "rate" | "amount" | "balance"
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
    
    /// Analyze division before multiplication patterns
    fn analyze_division_before_multiplication_patterns(&mut self, function: &SwayFunction) {
        // Check if we have both division and multiplication operations
        if !self.division_operations.is_empty() && !self.multiplication_operations.is_empty() {
            // Check if we're in a financial context
            let is_financial_context = !self.financial_operations.is_empty();
            
            if is_financial_context {
                self.findings.push(AstFinding::new(
                    "division_before_multiplication",
                    "Medium",
                    "Division before multiplication detected in financial context. This may cause precision loss.",
                    (function.span.start, function.span.end),
                    format!("Division operations: {}, Multiplication operations: {}", 
                        self.division_operations.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>().join(", "),
                        self.multiplication_operations.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>().join(", ")
                    ),
                    "Consider reordering operations to perform multiplication before division to avoid precision loss."
                ));
            }
        }
        
        // Check for specific patterns that are known to cause issues
        for (div_op, div_line) in &self.division_operations {
            for (mul_op, mul_line) in &self.multiplication_operations {
                // Check if division and multiplication are related (same variables)
                if self.operations_share_variables(div_op, mul_op) {
                    self.findings.push(AstFinding::new(
                        "division_before_multiplication",
                        "Medium",
                        "Related division and multiplication operations detected. Potential precision loss.",
                        (*div_line, *mul_line),
                        format!("Division: {}, Multiplication: {}", div_op, mul_op),
                        "Reorder operations to perform multiplication before division."
                    ));
                }
            }
        }
    }
    
    /// Check if two operations share variables
    fn operations_share_variables(&self, op1: &str, op2: &str) -> bool {
        // Simple check for shared variables in operations
        let vars1: Vec<&str> = op1.split_whitespace().collect();
        let vars2: Vec<&str> = op2.split_whitespace().collect();
        
        for var1 in &vars1 {
            for var2 in &vars2 {
                if var1 == var2 && !var1.chars().all(|c| c.is_numeric() || c == '.') {
                    return true;
                }
            }
        }
        false
    }
}

impl Detector for DivisionBeforeMultiplicationDetector {
    fn name(&self) -> &'static str {
        "division_before_multiplication"
    }
    fn description(&self) -> &'static str {
        "Detects division before multiplication precision loss using advanced AST-based semantic analysis."
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
                if let Some(finding) = self.analyze_function_division_before_multiplication(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}