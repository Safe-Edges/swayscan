use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding, SemanticAnalyzer};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct AccessControlDetector;

impl AccessControlDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_access_control(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = AccessControlVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "access_control",
                Severity::High,
                Category::AccessControl,
                0.9,
                &format!("Access Control Vulnerability Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Access Control Detection
struct AccessControlVisitor {
    findings: Vec<AstFinding>,
    has_access_control_check: bool,
    has_msg_sender_check: bool,
    has_owner_check: bool,
    has_admin_check: bool,
    has_role_check: bool,
    public_functions_without_checks: Vec<String>,
    state_changing_operations: Vec<String>,
    current_function_has_proper_checks: bool,
}

impl AccessControlVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            has_access_control_check: false,
            has_msg_sender_check: false,
            has_owner_check: false,
            has_admin_check: false,
            has_role_check: false,
            public_functions_without_checks: Vec::new(),
            state_changing_operations: Vec::new(),
            current_function_has_proper_checks: false,
        }
    }
}

impl AstVisitor for AccessControlVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.has_access_control_check = false;
        self.has_msg_sender_check = false;
        self.has_owner_check = false;
        self.has_admin_check = false;
        self.has_role_check = false;
        self.public_functions_without_checks.clear();
        self.state_changing_operations.clear();
        self.current_function_has_proper_checks = false;
        
        // Check if this is a public function that needs access control
        let is_public = matches!(function.visibility, crate::parser::FunctionVisibility::Public);
        let has_state_changes = !function.storage_writes.is_empty() || !function.external_calls.is_empty();
        
        if is_public && has_state_changes {
            // Visit all statements in the function body
            for statement in &function.body {
                self.visit_statement(statement);
            }
            
            // Analyze access control patterns
            self.analyze_access_control_patterns(function);
        }
        
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
                // Check for access control checks in if conditions
                self.check_access_control_in_condition(&if_stmt.condition);
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
                // Track state changing operations
                match storage_stmt.operation {
                    crate::parser::StorageOperation::Write | crate::parser::StorageOperation::Both => {
                        self.state_changing_operations.push(storage_stmt.field.clone());
                    }
                    _ => {}
                }
            }
            StatementKind::Require(require_stmt) => {
                // Check for access control in require statements
                self.check_access_control_in_condition(&require_stmt.condition);
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
                // Check for access control function calls
                if func_call.function == "msg_sender" {
                    self.has_msg_sender_check = true;
                }
                
                if func_call.function == "owner" || func_call.function == "is_owner" {
                    self.has_owner_check = true;
                }
                
                if func_call.function == "admin" || func_call.function == "is_admin" {
                    self.has_admin_check = true;
                }
                
                if func_call.function == "has_role" || func_call.function == "check_role" {
                    self.has_role_check = true;
                }
                
                // Check for access control patterns
                if SemanticAnalyzer::is_access_control_check(&SwayExpression {
                    kind: ExpressionKind::FunctionCall(func_call.clone()),
                    span: func_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                }) {
                    self.has_access_control_check = true;
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for access control method calls
                if method_call.method == "sender" || method_call.method == "caller" {
                    self.has_msg_sender_check = true;
                }
                
                if method_call.method == "owner" || method_call.method == "admin" {
                    self.has_owner_check = true;
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for access control comparisons
                if SemanticAnalyzer::is_access_control_check(&SwayExpression {
                    kind: ExpressionKind::Binary(binary_expr.clone()),
                    span: binary_expr.left.span.clone(),
                }) {
                    self.has_access_control_check = true;
                }
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
                self.check_access_control_in_condition(&if_expr.condition);
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

impl AccessControlVisitor {
    /// Check for access control patterns in conditional expressions
    fn check_access_control_in_condition(&mut self, condition: &SwayExpression) {
        if SemanticAnalyzer::is_access_control_check(condition) {
            self.has_access_control_check = true;
        }
        
        // Check for msg_sender comparisons
        if SemanticAnalyzer::is_msg_sender_call(condition) {
            self.has_msg_sender_check = true;
        }
    }
    
    /// Analyze access control patterns in the function
    fn analyze_access_control_patterns(&mut self, function: &SwayFunction) {
        // Check if public function with state changes lacks proper access control
        if !self.has_access_control_check && !self.state_changing_operations.is_empty() {
            self.findings.push(AstFinding::new(
                "access_control",
                "High",
                "Public function with state changes lacks proper access control checks.",
                (function.span.start, function.span.end),
                format!("State changing operations: {}", self.state_changing_operations.join(", ")),
                "Add access control checks using msg_sender, owner checks, or role-based access control."
            ));
        }
        
        // Check for weak access control patterns
        if self.has_msg_sender_check && !self.has_owner_check && !self.has_admin_check && !self.has_role_check {
            self.findings.push(AstFinding::new(
                "access_control",
                "Medium",
                "Weak access control pattern detected. Consider using role-based access control.",
                (function.span.start, function.span.end),
                "Function uses msg_sender check without proper role or ownership verification.",
                "Implement role-based access control or ownership verification for better security."
            ));
        }
    }
}

impl Detector for AccessControlDetector {
    fn name(&self) -> &'static str {
        "access_control"
    }
    fn description(&self) -> &'static str {
        "Detects access control vulnerabilities using advanced AST-based semantic analysis."
    }
    fn category(&self) -> Category {
        Category::AccessControl
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_access_control(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 