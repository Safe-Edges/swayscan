use crate::parser::{SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};

/// AST Visitor trait for semantic analysis
pub trait AstVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding>;
    fn visit_statement(&mut self, statement: &SwayStatement) -> Vec<AstFinding>;
    fn visit_expression(&mut self, expression: &SwayExpression) -> Vec<AstFinding>;
    fn visit_statement_kind(&mut self, kind: &StatementKind) -> Vec<AstFinding>;
    fn visit_expression_kind(&mut self, kind: &ExpressionKind) -> Vec<AstFinding>;
}

/// AST Finding for semantic analysis results
#[derive(Debug, Clone)]
pub struct AstFinding {
    pub finding_type: String,
    pub severity: String,
    pub message: String,
    pub span: (usize, usize),
    pub context: String,
    pub suggestion: String,
}

impl AstFinding {
    pub fn new(
        finding_type: impl Into<String>,
        severity: impl Into<String>,
        message: impl Into<String>,
        span: (usize, usize),
        context: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            finding_type: finding_type.into(),
            severity: severity.into(),
            message: message.into(),
            span,
            context: context.into(),
            suggestion: suggestion.into(),
        }
    }
}

/// Base AST Visitor implementation
pub struct BaseAstVisitor;

impl AstVisitor for BaseAstVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        let mut findings = Vec::new();
        
        // Visit all statements in the function body
        for statement in &function.body {
            findings.extend(self.visit_statement(statement));
        }
        
        findings
    }

    fn visit_statement(&mut self, statement: &SwayStatement) -> Vec<AstFinding> {
        self.visit_statement_kind(&statement.kind)
    }

    fn visit_expression(&mut self, expression: &SwayExpression) -> Vec<AstFinding> {
        self.visit_expression_kind(&expression.kind)
    }

    fn visit_statement_kind(&mut self, kind: &StatementKind) -> Vec<AstFinding> {
        match kind {
            StatementKind::Expression(expr) => self.visit_expression(expr),
            StatementKind::Let(let_stmt) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&let_stmt.value));
                findings
            }
            StatementKind::Return(expr_opt) => {
                if let Some(expr) = expr_opt {
                    self.visit_expression(expr)
                } else {
                    Vec::new()
                }
            }
            StatementKind::If(if_stmt) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&if_stmt.condition));
                
                for stmt in &if_stmt.then_block {
                    findings.extend(self.visit_statement(stmt));
                }
                
                if let Some(else_block) = &if_stmt.else_block {
                    for stmt in else_block {
                        findings.extend(self.visit_statement(stmt));
                    }
                }
                
                findings
            }
            StatementKind::While(while_stmt) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&while_stmt.condition));
                
                for stmt in &while_stmt.body {
                    findings.extend(self.visit_statement(stmt));
                }
                
                findings
            }
            StatementKind::For(for_stmt) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&for_stmt.iterator));
                
                for stmt in &for_stmt.body {
                    findings.extend(self.visit_statement(stmt));
                }
                
                findings
            }
            StatementKind::Match(match_stmt) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&match_stmt.expression));
                
                for arm in &match_stmt.arms {
                    if let Some(guard) = &arm.guard {
                        findings.extend(self.visit_expression(guard));
                    }
                    
                    for stmt in &arm.body {
                        findings.extend(self.visit_statement(stmt));
                    }
                }
                
                findings
            }
            StatementKind::Block(statements) => {
                let mut findings = Vec::new();
                for stmt in statements {
                    findings.extend(self.visit_statement(stmt));
                }
                findings
            }
            StatementKind::Storage(storage_stmt) => {
                // Handle storage operations
                Vec::new()
            }
            StatementKind::Require(require_stmt) => {
                self.visit_expression(&require_stmt.condition)
            }
            StatementKind::Assert(assert_stmt) => {
                self.visit_expression(&assert_stmt.condition)
            }
            StatementKind::Break | StatementKind::Continue => Vec::new(),
        }
    }

    fn visit_expression_kind(&mut self, kind: &ExpressionKind) -> Vec<AstFinding> {
        match kind {
            ExpressionKind::Literal(_) => Vec::new(),
            ExpressionKind::Variable(_) => Vec::new(),
            ExpressionKind::FunctionCall(func_call) => {
                let mut findings = Vec::new();
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    findings.extend(self.visit_expression(arg));
                }
                
                findings
            }
            ExpressionKind::MethodCall(method_call) => {
                let mut findings = Vec::new();
                
                findings.extend(self.visit_expression(&method_call.receiver));
                
                for arg in &method_call.arguments {
                    findings.extend(self.visit_expression(arg));
                }
                
                findings
            }
            ExpressionKind::Binary(binary_expr) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&binary_expr.left));
                findings.extend(self.visit_expression(&binary_expr.right));
                findings
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand)
            }
            ExpressionKind::If(if_expr) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&if_expr.condition));
                findings.extend(self.visit_expression(&if_expr.then_expr));
                
                if let Some(else_expr) = &if_expr.else_expr {
                    findings.extend(self.visit_expression(else_expr));
                }
                
                findings
            }
            ExpressionKind::Match(match_expr) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&match_expr.expression));
                
                for arm in &match_expr.arms {
                    if let Some(guard) = &arm.guard {
                        findings.extend(self.visit_expression(guard));
                    }
                    
                    for stmt in &arm.body {
                        findings.extend(self.visit_statement(stmt));
                    }
                }
                
                findings
            }
            ExpressionKind::Block(statements) => {
                let mut findings = Vec::new();
                for stmt in statements {
                    findings.extend(self.visit_statement(stmt));
                }
                findings
            }
            ExpressionKind::Array(expressions) => {
                let mut findings = Vec::new();
                for expr in expressions {
                    findings.extend(self.visit_expression(expr));
                }
                findings
            }
            ExpressionKind::Tuple(expressions) => {
                let mut findings = Vec::new();
                for expr in expressions {
                    findings.extend(self.visit_expression(expr));
                }
                findings
            }
            ExpressionKind::Struct(struct_expr) => {
                let mut findings = Vec::new();
                for field in &struct_expr.fields {
                    findings.extend(self.visit_expression(&field.value));
                }
                findings
            }
            ExpressionKind::Index(index_expr) => {
                let mut findings = Vec::new();
                findings.extend(self.visit_expression(&index_expr.array));
                findings.extend(self.visit_expression(&index_expr.index));
                findings
            }
            ExpressionKind::Field(field_expr) => {
                self.visit_expression(&field_expr.receiver)
            }
            ExpressionKind::Parenthesized(expr) => {
                self.visit_expression(expr)
            }
        }
    }
}

/// Semantic analysis utilities
pub struct SemanticAnalyzer;

impl SemanticAnalyzer {
    /// Check if an expression is a function call to a specific function
    pub fn is_function_call(expr: &SwayExpression, function_name: &str) -> bool {
        if let ExpressionKind::FunctionCall(func_call) = &expr.kind {
            func_call.function == function_name
        } else {
            false
        }
    }

    /// Check if an expression is a method call on a specific receiver
    pub fn is_method_call(expr: &SwayExpression, receiver: &str, method: &str) -> bool {
        if let ExpressionKind::MethodCall(method_call) = &expr.kind {
            method_call.method == method && Self::is_receiver(expr, receiver)
        } else {
            false
        }
    }

    /// Check if an expression represents a specific receiver
    pub fn is_receiver(expr: &SwayExpression, receiver: &str) -> bool {
        if let ExpressionKind::Variable(var_name) = &expr.kind {
            var_name == receiver
        } else {
            false
        }
    }

    /// Check if an expression is a binary operation with specific operator
    pub fn is_binary_operation(expr: &SwayExpression, operator: &str) -> bool {
        if let ExpressionKind::Binary(binary_expr) = &expr.kind {
            binary_expr.operator == operator
        } else {
            false
        }
    }

    /// Check if an expression is a literal with specific value
    pub fn is_literal(expr: &SwayExpression, value: &str) -> bool {
        if let ExpressionKind::Literal(literal) = &expr.kind {
            literal.value == value
        } else {
            false
        }
    }

    /// Check if an expression is a boolean literal
    pub fn is_boolean_literal(expr: &SwayExpression) -> bool {
        if let ExpressionKind::Literal(literal) = &expr.kind {
            literal.value == "true" || literal.value == "false"
        } else {
            false
        }
    }

    /// Check if an expression is a comparison operation
    pub fn is_comparison_operation(expr: &SwayExpression) -> bool {
        if let ExpressionKind::Binary(binary_expr) = &expr.kind {
            matches!(
                binary_expr.operator.as_str(),
                "==" | "!=" | "<" | ">" | "<=" | ">="
            )
        } else {
            false
        }
    }

    /// Check if an expression is an arithmetic operation
    pub fn is_arithmetic_operation(expr: &SwayExpression) -> bool {
        if let ExpressionKind::Binary(binary_expr) = &expr.kind {
            matches!(
                binary_expr.operator.as_str(),
                "+" | "-" | "*" | "/" | "%"
            )
        } else {
            false
        }
    }

    /// Check if an expression is a storage access
    pub fn is_storage_access(expr: &SwayExpression) -> bool {
        if let ExpressionKind::Field(field_expr) = &expr.kind {
            field_expr.field.starts_with("storage.")
        } else {
            false
        }
    }

    /// Check if an expression is an external call
    pub fn is_external_call(expr: &SwayExpression) -> bool {
        Self::is_function_call(expr, "transfer") ||
        Self::is_function_call(expr, "mint_to") ||
        Self::is_function_call(expr, "burn") ||
        Self::is_function_call(expr, "force_transfer_to_contract") ||
        Self::is_method_call(expr, "storage", "write") ||
        Self::is_method_call(expr, "storage", "insert")
    }

    /// Check if an expression is a state change operation
    pub fn is_state_change(expr: &SwayExpression) -> bool {
        Self::is_method_call(expr, "storage", "write") ||
        Self::is_method_call(expr, "storage", "insert") ||
        Self::is_method_call(expr, "storage", "remove")
    }

    /// Check if an expression is a require statement
    pub fn is_require_statement(expr: &SwayExpression) -> bool {
        Self::is_function_call(expr, "require")
    }

    /// Check if an expression is an assert statement
    pub fn is_assert_statement(expr: &SwayExpression) -> bool {
        Self::is_function_call(expr, "assert")
    }

    /// Check if an expression is a msg_sender call
    pub fn is_msg_sender_call(expr: &SwayExpression) -> bool {
        Self::is_function_call(expr, "msg_sender")
    }

    /// Check if an expression is an access control check
    pub fn is_access_control_check(expr: &SwayExpression) -> bool {
        if let ExpressionKind::Binary(binary_expr) = &expr.kind {
            if binary_expr.operator == "==" {
                // Check if one side is msg_sender() and the other is a variable
                let left_is_msg_sender = Self::is_msg_sender_call(&binary_expr.left);
                let right_is_msg_sender = Self::is_msg_sender_call(&binary_expr.right);
                
                if left_is_msg_sender || right_is_msg_sender {
                    // Check if the other side is a variable (likely owner/admin)
                    if let ExpressionKind::Variable(_) = binary_expr.left.kind {
                        return true;
                    }
                    if let ExpressionKind::Variable(_) = binary_expr.right.kind {
                        return true;
                    }
                }
            }
        }
        false
    }
} 