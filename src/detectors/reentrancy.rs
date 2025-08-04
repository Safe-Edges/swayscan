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

        // Track the order of operations
        let mut op_timeline = Vec::new(); // Vec<(op_type, desc)>
        fn walk_for_ops(stmts: &[SwayStatement], op_timeline: &mut Vec<(String, String)>, guard: &mut bool) {
            use crate::parser::StatementKind::*;
            for stmt in stmts {
                match &stmt.kind {
                    Storage(storage_stmt) => {
                        if storage_stmt.operation == crate::parser::StorageOperation::Write || storage_stmt.operation == crate::parser::StorageOperation::Both {
                            op_timeline.push(("state_change".to_string(), storage_stmt.field.clone()));
                        }
                    }
                    Expression(expr) => {
                        walk_expr_for_ops(expr, op_timeline, guard);
                    }
                    Require(_) | Assert(_) => {}
                    If(if_stmt) => {
                        walk_for_ops(&if_stmt.then_block, op_timeline, guard);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_ops(else_block, op_timeline, guard);
                        }
                    }
                    While(while_stmt) => walk_for_ops(&while_stmt.body, op_timeline, guard),
                    For(for_stmt) => walk_for_ops(&for_stmt.body, op_timeline, guard),
                    Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_ops(&arm.body, op_timeline, guard);
                        }
                    }
                    Block(stmts) => walk_for_ops(stmts, op_timeline, guard),
                    _ => {}
                }
            }
        }
        fn walk_expr_for_ops(expr: &SwayExpression, op_timeline: &mut Vec<(String, String)>, guard: &mut bool) {
            use crate::parser::ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    let func = call.function.as_str();
                    // Recognize Sway-specific external calls
                    if ["transfer", "mint_to", "call", "call_with_function_selector", "force_transfer_to_contract", "transfer_to_address"].contains(&func) {
                        op_timeline.push(("external_call".to_string(), func.to_string()));
                    }
                    // Recognize custom reentrancy guards
                    if func == "non_reentrant" || func == "reentrancy_guard" || func.contains("no_reentrancy") {
                        *guard = true;
                    }
                    for arg in &call.arguments {
                        walk_expr_for_ops(arg, op_timeline, guard);
                    }
                }
                MethodCall(mc) => {
                    walk_expr_for_ops(&mc.receiver, op_timeline, guard);
                    for arg in &mc.arguments {
                        walk_expr_for_ops(arg, op_timeline, guard);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_ops(&bin.left, op_timeline, guard);
                    walk_expr_for_ops(&bin.right, op_timeline, guard);
                }
                Unary(u) => walk_expr_for_ops(&u.operand, op_timeline, guard),
                If(if_expr) => {
                    walk_expr_for_ops(&if_expr.condition, op_timeline, guard);
                    walk_expr_for_ops(&if_expr.then_expr, op_timeline, guard);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_ops(else_expr, op_timeline, guard);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_ops(&match_expr.expression, op_timeline, guard);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let crate::parser::StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_ops(e, op_timeline, guard);
                            }
                        }
                    }
                }
                Block(stmts) => walk_for_ops(stmts, op_timeline, guard),
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_ops(e, op_timeline, guard);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_ops(&f.value, op_timeline, guard);
                    }
                }
                Index(idx) => {
                    walk_expr_for_ops(&idx.array, op_timeline, guard);
                    walk_expr_for_ops(&idx.index, op_timeline, guard);
                }
                Field(fe) => walk_expr_for_ops(&fe.receiver, op_timeline, guard),
                Parenthesized(e) => walk_expr_for_ops(e, op_timeline, guard),
                _ => {}
            }
        }
        walk_for_ops(&function.body, &mut op_timeline, &mut self.has_reentrancy_guard);
        // Print the operation timeline for debugging

        // Analyze order: look for external call before state change
        let mut found_external_before_state = false;
        let mut found_state_before_external = false;
        let mut first_external = None;
        let mut first_state = None;
        for (i, (op, desc)) in op_timeline.iter().enumerate() {
            if op == "external_call" && first_external.is_none() {
                first_external = Some(i);
            }
            if op == "state_change" && first_state.is_none() {
                first_state = Some(i);
            }
        }
        if let (Some(ext_idx), Some(st_idx)) = (first_external, first_state) {
            if ext_idx < st_idx {
                found_external_before_state = true;
            } else if st_idx < ext_idx {
                found_state_before_external = true;
            }
        }
        // Report findings
        if found_external_before_state {
            self.findings.push(AstFinding::new(
                "reentrancy",
                "High",
                "Reentrancy risk: external call occurs before state change.",
                (function.span.start, function.span.end),
                format!("Order: {:?}", op_timeline),
                "Move state changes before external calls and/or add a reentrancy guard.",
            ));
        } else if found_state_before_external && !self.has_reentrancy_guard {
            self.findings.push(AstFinding::new(
                "reentrancy",
                "Medium",
                "Potential reentrancy: state change before external call, but no reentrancy guard.",
                (function.span.start, function.span.end),
                format!("Order: {:?}", op_timeline),
                "Consider adding a reentrancy guard for extra safety.",
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