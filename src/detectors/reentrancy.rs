use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding, SemanticAnalyzer};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct ReentrancyDetector;

impl ReentrancyDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_reentrancy(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = ReentrancyVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "reentrancy",
                Severity::High,
                Category::Security,
                0.9,
                &format!("Reentrancy Vulnerability Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Reentrancy Detection
struct ReentrancyVisitor {
    findings: Vec<AstFinding>,
    state_changes_before_external_call: Vec<String>,
    external_calls_before_state_change: Vec<String>,
    has_checks_effects_interactions: bool,
    has_reentrancy_guard: bool,
    current_function_state_changes: Vec<String>,
    current_function_external_calls: Vec<String>,
}

impl ReentrancyVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            state_changes_before_external_call: Vec::new(),
            external_calls_before_state_change: Vec::new(),
            has_checks_effects_interactions: false,
            has_reentrancy_guard: false,
            current_function_state_changes: Vec::new(),
            current_function_external_calls: Vec::new(),
        }
    }
}

impl AstVisitor for ReentrancyVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.state_changes_before_external_call.clear();
        self.external_calls_before_state_change.clear();
        self.has_checks_effects_interactions = false;
        self.has_reentrancy_guard = false;
        self.current_function_state_changes.clear();
        self.current_function_external_calls.clear();
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Analyze the order of operations for reentrancy vulnerabilities
        self.analyze_reentrancy_patterns(function);
        
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
            StatementKind::Storage(storage_stmt) => {
                // Track storage operations for reentrancy analysis
                match storage_stmt.operation {
                    crate::parser::StorageOperation::Write | crate::parser::StorageOperation::Both => {
                        self.current_function_state_changes.push(storage_stmt.field.clone());
                    }
                    _ => {}
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
            ExpressionKind::Variable(_) => {}
            ExpressionKind::FunctionCall(func_call) => {
                // Check for external calls and reentrancy guards
                if SemanticAnalyzer::is_external_call(&SwayExpression {
                    kind: ExpressionKind::FunctionCall(func_call.clone()),
                    span: func_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                }) {
                    self.current_function_external_calls.push(func_call.function.clone());
                }
                
                // Check for reentrancy guard patterns
                if func_call.function == "non_reentrant" || func_call.function == "reentrancy_guard" {
                    self.has_reentrancy_guard = true;
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check for external calls and state changes
                if SemanticAnalyzer::is_external_call(&SwayExpression {
                    kind: ExpressionKind::MethodCall(method_call.clone()),
                    span: method_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                }) {
                    self.current_function_external_calls.push(format!("{}.{}", "receiver", method_call.method));
                }
                
                if SemanticAnalyzer::is_state_change(&SwayExpression {
                    kind: ExpressionKind::MethodCall(method_call.clone()),
                    span: method_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                }) {
                    self.current_function_state_changes.push(format!("{}.{}", "receiver", method_call.method));
                }
                
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
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

impl ReentrancyVisitor {
    /// Analyze reentrancy patterns in the function
    fn analyze_reentrancy_patterns(&mut self, function: &SwayFunction) {
        // Check if function has external calls and state changes
        if !self.current_function_external_calls.is_empty() && !self.current_function_state_changes.is_empty() {
            // Check if reentrancy guard is missing
            if !self.has_reentrancy_guard {
                self.findings.push(AstFinding::new(
                    "reentrancy",
                    "High",
                    "Potential reentrancy vulnerability detected. External calls without reentrancy protection.",
                    (function.span.start, function.span.end),
                    format!("External calls: {}, State changes: {}", 
                        self.current_function_external_calls.join(", "),
                        self.current_function_state_changes.join(", ")
                    ),
                    "Implement reentrancy guards or follow checks-effects-interactions pattern."
                ));
            }
            
            // Check for proper order of operations (checks-effects-interactions)
            if !self.has_checks_effects_interactions {
                self.findings.push(AstFinding::new(
                    "reentrancy",
                    "High",
                    "Potential reentrancy vulnerability. State changes may occur before external calls.",
                    (function.span.start, function.span.end),
                    "Function performs state changes and external calls without proper ordering.",
                    "Follow checks-effects-interactions pattern: validate → update state → external call."
                ));
            }
        }
    }
}

impl Detector for ReentrancyDetector {
    fn name(&self) -> &'static str {
        "reentrancy"
    }
    fn description(&self) -> &'static str {
        "Detects reentrancy vulnerabilities using advanced AST-based semantic analysis."
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
                if let Some(finding) = self.analyze_function_reentrancy(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 