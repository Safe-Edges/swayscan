use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding, SemanticAnalyzer};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct ExternalCallInLoopDetector;

impl ExternalCallInLoopDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_external_call_in_loop(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = ExternalCallInLoopVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "external_call_in_loop",
                Severity::High,
                Category::ExternalCalls,
                0.9,
                &format!("External Call in Loop Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for External Call in Loop Detection
struct ExternalCallInLoopVisitor {
    findings: Vec<AstFinding>,
    current_loop_depth: usize,
    external_calls_in_loop: Vec<(String, usize)>, // (call_name, line_number)
    has_gas_limit: bool,
    has_bounds_check: bool,
}

impl ExternalCallInLoopVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            current_loop_depth: 0,
            external_calls_in_loop: Vec::new(),
            has_gas_limit: false,
            has_bounds_check: false,
        }
    }
}

impl AstVisitor for ExternalCallInLoopVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        self.current_loop_depth = 0;
        self.external_calls_in_loop.clear();
        self.has_gas_limit = false;
        self.has_bounds_check = false;
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
        }
        
        // Check if we found external calls in loops without proper protection
        if !self.external_calls_in_loop.is_empty() && !self.has_gas_limit && !self.has_bounds_check {
            let calls_list = self.external_calls_in_loop.iter()
                .map(|(call, _)| call.clone())
                .collect::<Vec<_>>()
                .join(", ");
            
            self.findings.push(AstFinding::new(
                "external_call_in_loop",
                "High",
                "External calls detected within loops without gas limits or bounds checking.",
                (function.span.start, function.span.end),
                format!("External calls in loop: {}", calls_list),
                "Add gas limits, bounds checking, or use pull-over-push pattern to avoid external calls in loops."
            ));
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
                // Enter loop context
                self.current_loop_depth += 1;
                
                self.visit_expression(&while_stmt.condition);
                
                for stmt in &while_stmt.body {
                    self.visit_statement(stmt);
                }
                
                // Exit loop context
                self.current_loop_depth -= 1;
            }
            StatementKind::For(for_stmt) => {
                // Enter loop context
                self.current_loop_depth += 1;
                
                self.visit_expression(&for_stmt.iterator);
                
                for stmt in &for_stmt.body {
                    self.visit_statement(stmt);
                }
                
                // Exit loop context
                self.current_loop_depth -= 1;
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
                // Check if this is an external call within a loop
                if self.current_loop_depth > 0 {
                    if SemanticAnalyzer::is_external_call(&SwayExpression {
                        kind: ExpressionKind::FunctionCall(func_call.clone()),
                        span: func_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                    }) {
                        self.external_calls_in_loop.push((
                            func_call.function.clone(),
                            func_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                        ));
                    }
                    
                    // Check for gas limit or bounds checking
                    if func_call.function == "gas_limit" || func_call.function == "max_iterations" {
                        self.has_gas_limit = true;
                    }
                }
                
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                // Check if this is an external call within a loop
                if self.current_loop_depth > 0 {
                    if SemanticAnalyzer::is_external_call(&SwayExpression {
                        kind: ExpressionKind::MethodCall(method_call.clone()),
                        span: method_call.arguments.first().map(|a| a.span.clone()).unwrap_or_default(),
                    }) {
                        self.external_calls_in_loop.push((
                            format!("{}.{}", "receiver", method_call.method),
                            method_call.arguments.first().map(|a| a.span.start).unwrap_or(0)
                        ));
                    }
                    
                    // Check for bounds checking
                    if method_call.method == "bounds" || method_call.method == "check" {
                        self.has_bounds_check = true;
                    }
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

impl Detector for ExternalCallInLoopDetector {
    fn name(&self) -> &'static str {
        "external_call_in_loop"
    }
    fn description(&self) -> &'static str {
        "Detects external calls within loops using advanced AST-based semantic analysis."
    }
    fn category(&self) -> Category {
        Category::ExternalCalls
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_external_call_in_loop(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}