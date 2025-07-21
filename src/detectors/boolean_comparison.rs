use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, StatementKind, ExpressionKind};
use crate::detectors::ast_visitor::{AstVisitor, AstFinding, SemanticAnalyzer};
use crate::utils::{byte_offset_to_line, byte_offset_to_line_col};

pub struct BooleanComparisonDetector;

impl BooleanComparisonDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_boolean_comparison(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        let mut visitor = BooleanComparisonVisitor::new();
        let ast_findings = visitor.visit_function(function);
        
        if !ast_findings.is_empty() {
            let finding = &ast_findings[0]; // Take the first finding
            let (line_number, column) = byte_offset_to_line_col(&file.content, finding.span.0);
            
            Some(Finding::new(
                "boolean_comparison",
                Severity::Low,
                Category::LogicErrors,
                0.8,
                &format!("Boolean Comparison Issue Detected - {} (line {}, col {})", function.name, line_number, column),
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

/// Advanced AST Visitor for Boolean Comparison Detection
struct BooleanComparisonVisitor {
    findings: Vec<AstFinding>,
}

impl BooleanComparisonVisitor {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl AstVisitor for BooleanComparisonVisitor {
    fn visit_function(&mut self, function: &SwayFunction) -> Vec<AstFinding> {
        self.findings.clear();
        
        // Visit all statements in the function body
        for statement in &function.body {
            self.visit_statement(statement);
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
                // Check for boolean comparison in if condition
                self.check_boolean_comparison_in_condition(&if_stmt.condition);
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
                // Check for boolean comparison in while condition
                self.check_boolean_comparison_in_condition(&while_stmt.condition);
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
                // Visit all arguments
                for arg in &func_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::MethodCall(method_call) => {
                self.visit_expression(&method_call.receiver);
                
                for arg in &method_call.arguments {
                    self.visit_expression(arg);
                }
            }
            ExpressionKind::Binary(binary_expr) => {
                // Check for boolean comparison patterns
                self.check_boolean_comparison_pattern(binary_expr);
                
                self.visit_expression(&binary_expr.left);
                self.visit_expression(&binary_expr.right);
            }
            ExpressionKind::Unary(unary_expr) => {
                self.visit_expression(&unary_expr.operand);
            }
            ExpressionKind::If(if_expr) => {
                self.check_boolean_comparison_in_condition(&if_expr.condition);
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

impl BooleanComparisonVisitor {
    /// Check for boolean comparison patterns in binary expressions
    fn check_boolean_comparison_pattern(&mut self, binary_expr: &crate::parser::BinaryExpression) {
        // Check for == true or == false patterns
        if binary_expr.operator == "==" {
            let left_is_bool = SemanticAnalyzer::is_boolean_literal(&binary_expr.left);
            let right_is_bool = SemanticAnalyzer::is_boolean_literal(&binary_expr.right);
            
            if left_is_bool || right_is_bool {
                self.findings.push(AstFinding::new(
                    "boolean_comparison",
                    "Low",
                    "Unnecessary boolean comparison detected. Direct boolean usage is more efficient.",
                    (binary_expr.left.span.start, binary_expr.right.span.end),
                    format!("Comparison: {} == {}", 
                        if left_is_bool { "boolean_literal" } else { "expression" },
                        if right_is_bool { "boolean_literal" } else { "expression" }
                    ),
                    "Remove the boolean comparison and use the expression directly in conditions."
                ));
            }
        }
        
        // Check for != true or != false patterns
        if binary_expr.operator == "!=" {
            let left_is_bool = SemanticAnalyzer::is_boolean_literal(&binary_expr.left);
            let right_is_bool = SemanticAnalyzer::is_boolean_literal(&binary_expr.right);
            
            if left_is_bool || right_is_bool {
                self.findings.push(AstFinding::new(
                    "boolean_comparison",
                    "Low",
                    "Unnecessary boolean comparison detected. Use logical negation instead.",
                    (binary_expr.left.span.start, binary_expr.right.span.end),
                    format!("Comparison: {} != {}", 
                        if left_is_bool { "boolean_literal" } else { "expression" },
                        if right_is_bool { "boolean_literal" } else { "expression" }
                    ),
                    "Use logical negation (!expression) instead of boolean comparison."
                ));
            }
        }
    }
    
    /// Check for boolean comparison in conditional expressions
    fn check_boolean_comparison_in_condition(&mut self, condition: &SwayExpression) {
        // This will be called by the visitor pattern when visiting if/while conditions
        // The actual checking is done in check_boolean_comparison_pattern
        self.visit_expression(condition);
    }
}

impl Detector for BooleanComparisonDetector {
    fn name(&self) -> &'static str {
        "boolean_comparison"
    }
    fn description(&self) -> &'static str {
        "Detects unnecessary boolean comparisons using advanced AST-based semantic analysis."
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
                if let Some(finding) = self.analyze_function_boolean_comparison(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}