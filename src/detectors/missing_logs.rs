use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct MissingLogsDetector;

impl MissingLogsDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_missing_logs(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        use crate::parser::{StatementKind, ExpressionKind, SwayStatement, SwayExpression};
        struct LogState {
            has_critical_op: bool,
            has_logging: bool,
        }
        fn walk_for_logs(stmts: &[SwayStatement], state: &mut LogState) {
            for stmt in stmts {
                match &stmt.kind {
                    StatementKind::Storage(storage_stmt) => {
                        if storage_stmt.operation == crate::parser::StorageOperation::Write {
                            state.has_critical_op = true;
                        }
                    }
                    StatementKind::Expression(expr) => {
                        walk_expr_for_logs(expr, state);
                    }
                    StatementKind::If(if_stmt) => {
                        walk_for_logs(&if_stmt.then_block, state);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_logs(else_block, state);
                        }
                    }
                    StatementKind::While(while_stmt) => walk_for_logs(&while_stmt.body, state),
                    StatementKind::For(for_stmt) => walk_for_logs(&for_stmt.body, state),
                    StatementKind::Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_logs(&arm.body, state);
                        }
                    }
                    StatementKind::Block(stmts) => walk_for_logs(stmts, state),
                    _ => {}
                }
            }
        }
        fn walk_expr_for_logs(expr: &SwayExpression, state: &mut LogState) {
            use ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    // Detect critical operations
                    match call.function.as_str() {
                        "transfer" | "mint" | "burn" | "withdraw" | "deposit" | "stake" | "unstake" | "claim" => state.has_critical_op = true,
                        "emit" | "log" => state.has_logging = true,
                        _ => {}
                    };
                    for arg in &call.arguments {
                        walk_expr_for_logs(arg, state);
                    }
                }
                MethodCall(mc) => {
                    walk_expr_for_logs(&mc.receiver, state);
                    for arg in &mc.arguments {
                        walk_expr_for_logs(arg, state);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_logs(&bin.left, state);
                    walk_expr_for_logs(&bin.right, state);
                }
                Unary(u) => walk_expr_for_logs(&u.operand, state),
                If(if_expr) => {
                    walk_expr_for_logs(&if_expr.condition, state);
                    walk_expr_for_logs(&if_expr.then_expr, state);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_logs(else_expr, state);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_logs(&match_expr.expression, state);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_logs(e, state);
                            }
                        }
                    }
                }
                Block(stmts) => walk_for_logs(stmts, state),
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_logs(e, state);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_logs(&f.value, state);
                    }
                }
                Index(idx) => {
                    walk_expr_for_logs(&idx.array, state);
                    walk_expr_for_logs(&idx.index, state);
                }
                Field(fe) => walk_expr_for_logs(&fe.receiver, state),
                Parenthesized(e) => walk_expr_for_logs(e, state),
                _ => {}
            }
        }
        let mut state = LogState { has_critical_op: false, has_logging: false };
        walk_for_logs(&function.body, &mut state);
        if state.has_critical_op && !state.has_logging {
            let description = format!("Function '{}' contains critical operations without proper logging or event emission.", function.name);
            return Some(Finding::new(
                "missing_logs",
                Severity::Low,
                Category::Security,
                0.7,
                &format!("Missing Logs Detected - {}", function.name),
                &description,
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Add proper logging and event emissions for critical operations.",
            ));
        }
        None
    }
}

impl Detector for MissingLogsDetector {
    fn name(&self) -> &'static str {
        "missing_logs"
    }
    fn description(&self) -> &'static str {
        "Detects critical operations without proper logging mechanisms using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Security
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_missing_logs(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}