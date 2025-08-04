use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct UnprotectedStorageDetector;

impl UnprotectedStorageDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_unprotected_storage(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        use crate::parser::{StatementKind, ExpressionKind, SwayStatement, SwayExpression};
        struct StorageState {
            has_storage_write: bool,
            has_access_control: bool,
            storage_write_details: Vec<String>,
            access_control_details: Vec<String>,
        }
        fn walk_for_storage_checks(stmts: &[SwayStatement], state: &mut StorageState) {
            for stmt in stmts {
                match &stmt.kind {
                    StatementKind::Storage(storage_stmt) => {
                        if storage_stmt.operation == crate::parser::StorageOperation::Write || storage_stmt.operation == crate::parser::StorageOperation::Both {
                            state.has_storage_write = true;
                            state.storage_write_details.push(storage_stmt.field.clone());
                        }
                    }
                    StatementKind::Expression(expr) => {
                        walk_expr_for_storage_checks(expr, state);
                    }
                    StatementKind::Require(_) | StatementKind::Assert(_) => {
                        state.has_access_control = true;
                        state.access_control_details.push("require/assert".to_string());
                    }
                    StatementKind::If(if_stmt) => {
                        walk_for_storage_checks(&if_stmt.then_block, state);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_storage_checks(else_block, state);
                        }
                    }
                    StatementKind::While(while_stmt) => walk_for_storage_checks(&while_stmt.body, state),
                    StatementKind::For(for_stmt) => walk_for_storage_checks(&for_stmt.body, state),
                    StatementKind::Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_storage_checks(&arm.body, state);
                        }
                    }
                    StatementKind::Block(stmts) => walk_for_storage_checks(stmts, state),
                    _ => {}
                }
            }
        }
        fn walk_expr_for_storage_checks(expr: &SwayExpression, state: &mut StorageState) {
            use ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    let func = call.function.as_str();
                    // Check for access control patterns
                    if ["require", "assert", "only_owner", "has_role", "check_access", "validate_access"].contains(&func) {
                        state.has_access_control = true;
                        state.access_control_details.push(func.to_string());
                    }
                    // Check for storage write patterns
                    if func.contains("write") || func.contains("insert") || func.contains("set") {
                        state.has_storage_write = true;
                        state.storage_write_details.push(func.to_string());
                    }
                    for arg in &call.arguments {
                        walk_expr_for_storage_checks(arg, state);
                    }
                }
                MethodCall(mc) => {
                    let method = mc.method.as_str();
                    // Check for storage write methods
                    if ["write", "insert", "set", "update"].contains(&method) {
                        state.has_storage_write = true;
                        state.storage_write_details.push(format!("{}.{}", "receiver", method));
                    }
                    // Check for access control methods
                    if ["only_owner", "has_role", "check_access"].contains(&method) {
                        state.has_access_control = true;
                        state.access_control_details.push(format!("{}.{}", "receiver", method));
                    }
                    walk_expr_for_storage_checks(&mc.receiver, state);
                    for arg in &mc.arguments {
                        walk_expr_for_storage_checks(arg, state);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_storage_checks(&bin.left, state);
                    walk_expr_for_storage_checks(&bin.right, state);
                }
                Unary(u) => walk_expr_for_storage_checks(&u.operand, state),
                If(if_expr) => {
                    walk_expr_for_storage_checks(&if_expr.condition, state);
                    walk_expr_for_storage_checks(&if_expr.then_expr, state);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_storage_checks(else_expr, state);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_storage_checks(&match_expr.expression, state);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_storage_checks(e, state);
                            }
                        }
                    }
                }
                Block(stmts) => walk_for_storage_checks(stmts, state),
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_storage_checks(e, state);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_storage_checks(&f.value, state);
                    }
                }
                Index(idx) => {
                    walk_expr_for_storage_checks(&idx.array, state);
                    walk_expr_for_storage_checks(&idx.index, state);
                }
                Field(fe) => walk_expr_for_storage_checks(&fe.receiver, state),
                Parenthesized(e) => walk_expr_for_storage_checks(e, state),
                _ => {}
            }
        }
        let mut state = StorageState {
            has_storage_write: false,
            has_access_control: false,
            storage_write_details: Vec::new(),
            access_control_details: Vec::new(),
        };
        walk_for_storage_checks(&function.body, &mut state);
        // Only flag if storage write is performed without access control
        if state.has_storage_write && !state.has_access_control {
            let description = format!(
                "Function '{}' modifies storage without proper access control. Storage operations: {}. No access control detected.",
                function.name,
                state.storage_write_details.join(", ")
            );
            return Some(Finding::new(
                "unprotected_storage_variable",
                Severity::High,
                Category::Storage,
                0.9,
                &format!("Unprotected Storage Modification Detected - {}", function.name),
                &description,
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Add access control checks (require, assert, only_owner, etc.) before modifying storage variables.",
            ));
        }
        None
    }
}

impl Detector for UnprotectedStorageDetector {
    fn name(&self) -> &'static str {
        "unprotected_storage_variable"
    }
    fn description(&self) -> &'static str {
        "Finds storage modifications without access restrictions using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::Storage
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_unprotected_storage(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}