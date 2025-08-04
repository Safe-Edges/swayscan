use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct DataValidationDetector;

impl DataValidationDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_data_validation(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        use crate::parser::{StatementKind, ExpressionKind, SwayStatement, SwayExpression};
        let is_public = matches!(function.visibility, crate::parser::FunctionVisibility::Public);
        let mut called_by_public = false;
        for f in &ast.functions {
            if f.name != function.name && f.body.iter().any(|stmt| match &stmt.kind {
                StatementKind::Expression(expr) => {
                    if let ExpressionKind::FunctionCall(call) = &expr.kind {
                        call.function == function.name && matches!(f.visibility, crate::parser::FunctionVisibility::Public)
                    } else { false }
                }
                _ => false
            }) {
                called_by_public = true;
                break;
            }
        }
        if !is_public && !called_by_public {
            return None;
        }
        if function.storage_writes.is_empty() {
            return None;
        }

        // Helper: recursively walk statements/expressions to find validation for a param
        fn walk_for_validation(param: &crate::parser::SwayParameter, stmts: &[SwayStatement], found: &mut (bool, bool, bool)) {
            use crate::parser::StatementKind::*;
            for stmt in stmts {
                match &stmt.kind {
                    Require(req) => {
                        let cond = &req.condition;
                        let cond_str = format!("{}", cond);
                        // General validation
                        if cond_str.contains(&param.name) {
                            found.0 = true;
                        }
                        // Zero check
                        if (param.type_.name == "Address" || param.type_.name == "Identity" || param.type_.name == "ContractId") &&
                            (cond_str.contains(&format!("{} != Address::zero()", param.name)) ||
                             cond_str.contains(&format!("{} != Identity::zero()", param.name)) ||
                             cond_str.contains(&format!("{} != ContractId::zero()", param.name))) {
                            found.1 = true;
                        }
                        // Bounds check
                        if ["u8","u16","u32","u64","i8","i16","i32","i64","usize","isize","Vec<u8>","Vec<u64>","b256"].contains(&param.type_.name.as_str()) &&
                            (cond_str.contains(&format!("{} >", param.name)) || cond_str.contains(&format!("{} >=", param.name)) ||
                             cond_str.contains(&format!("{} <", param.name)) || cond_str.contains(&format!("{} <=", param.name))) {
                            found.2 = true;
                        }
                    }
                    Assert(assert) => {
                        let cond = &assert.condition;
                        let cond_str = format!("{}", cond);
                        // General validation
                        if cond_str.contains(&param.name) {
                            found.0 = true;
                        }
                        // Zero check
                        if (param.type_.name == "Address" || param.type_.name == "Identity" || param.type_.name == "ContractId") &&
                            (cond_str.contains(&format!("{} != Address::zero()", param.name)) ||
                             cond_str.contains(&format!("{} != Identity::zero()", param.name)) ||
                             cond_str.contains(&format!("{} != ContractId::zero()", param.name))) {
                            found.1 = true;
                        }
                        // Bounds check
                        if ["u8","u16","u32","u64","i8","i16","i32","i64","usize","isize","Vec<u8>","Vec<u64>","b256"].contains(&param.type_.name.as_str()) &&
                            (cond_str.contains(&format!("{} >", param.name)) || cond_str.contains(&format!("{} >=", param.name)) ||
                             cond_str.contains(&format!("{} <", param.name)) || cond_str.contains(&format!("{} <=", param.name))) {
                            found.2 = true;
                        }
                    }
                    Expression(expr) => {
                        walk_expr_for_validation(param, expr, found);
                    }
                    If(if_stmt) => {
                        walk_for_validation(param, &if_stmt.then_block, found);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_validation(param, else_block, found);
                        }
                    }
                    While(while_stmt) => {
                        walk_for_validation(param, &while_stmt.body, found);
                    }
                    For(for_stmt) => {
                        walk_for_validation(param, &for_stmt.body, found);
                    }
                    Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_validation(param, &arm.body, found);
                        }
                    }
                    Block(stmts) => {
                        walk_for_validation(param, stmts, found);
                    }
                    _ => {}
                }
            }
        }
        fn walk_expr_for_validation(param: &crate::parser::SwayParameter, expr: &SwayExpression, found: &mut (bool, bool, bool)) {
            use crate::parser::ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    for arg in &call.arguments {
                        walk_expr_for_validation(param, arg, found);
                    }
                }
                MethodCall(mc) => {
                    walk_expr_for_validation(param, &mc.receiver, found);
                    for arg in &mc.arguments {
                        walk_expr_for_validation(param, arg, found);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_validation(param, &bin.left, found);
                    walk_expr_for_validation(param, &bin.right, found);
                }
                Unary(u) => {
                    walk_expr_for_validation(param, &u.operand, found);
                }
                If(if_expr) => {
                    walk_expr_for_validation(param, &if_expr.condition, found);
                    walk_expr_for_validation(param, &if_expr.then_expr, found);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_validation(param, else_expr, found);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_validation(param, &match_expr.expression, found);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let crate::parser::StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_validation(param, e, found);
                            }
                        }
                    }
                }
                Block(stmts) => {
                    walk_for_validation(param, stmts, found);
                }
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_validation(param, e, found);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_validation(param, &f.value, found);
                    }
                }
                Index(idx) => {
                    walk_expr_for_validation(param, &idx.array, found);
                    walk_expr_for_validation(param, &idx.index, found);
                }
                Field(fe) => {
                    walk_expr_for_validation(param, &fe.receiver, found);
                }
                Parenthesized(e) => {
                    walk_expr_for_validation(param, e, found);
                }
                Variable(name) => {
                    if name == &param.name {
                        found.0 = true; // Used, but not necessarily validated
                    }
                }
                _ => {}
            }
        }

        let mut findings = Vec::new();
        let mut unused_params = Vec::new();
        for param in &function.parameters {
            let mut used = false;
            // Check if parameter is used in sensitive operations
            for stmt in &function.body {
                match &stmt.kind {
                    StatementKind::Storage(storage_stmt) => {
                        if storage_stmt.operation == crate::parser::StorageOperation::Write {
                            if function.content.contains(&param.name) {
                                used = true;
                            }
                        }
                    }
                    StatementKind::Expression(expr) => {
                        if format!("{}", expr).contains(&param.name) {
                            used = true;
                        }
                    }
                    _ => {}
                }
            }
            if !used {
                unused_params.push(param.name.clone());
                continue;
            }
            // Deep AST walk for validation
            let mut found = (false, false, false); // (general, zero, bounds)
            walk_for_validation(param, &function.body, &mut found);
            // Report missing validations
            if (param.type_.name == "Address" || param.type_.name == "Identity" || param.type_.name == "ContractId") && !found.1 {
                findings.push(Finding::new(
                    "data_validation",
                    Severity::Low,
                    Category::DataValidation,
                    0.9,
                    &format!("Missing Zero Value Check - {}", function.name),
                    &format!("Function '{}' uses parameter '{}' in sensitive operation without zero value check.", function.name, param.name),
                    &file.path,
                    function.span.start,
                    function.span.start,
                    &function.content,
                    "Add zero value check for Address/Identity/ContractId parameter.",
                ));
            }
            if ["u8","u16","u32","u64","i8","i16","i32","i64","usize","isize","Vec<u8>","Vec<u64>","b256"].contains(&param.type_.name.as_str()) && !found.2 {
                findings.push(Finding::new(
                    "data_validation",
                    Severity::Low,
                    Category::DataValidation,
                    0.8,
                    &format!("Missing Bounds Check - {}", function.name),
                    &format!("Function '{}' uses parameter '{}' in sensitive operation without bounds check.", function.name, param.name),
                    &file.path,
                    function.span.start,
                    function.span.start,
                    &function.content,
                    "Add bounds check for numeric/array parameter.",
                ));
            }
            if !found.0 {
                findings.push(Finding::new(
                    "data_validation",
                    Severity::Low,
                    Category::DataValidation,
                    0.7,
                    &format!("Missing General Validation - {}", function.name),
                    &format!("Function '{}' uses parameter '{}' in sensitive operation without validation.", function.name, param.name),
                    &file.path,
                    function.span.start,
                    function.span.start,
                    &function.content,
                    "Add require/assert validation for parameter used in sensitive operation.",
                ));
            }
        }
        if !unused_params.is_empty() {
            findings.push(Finding::new(
                "data_validation",
                Severity::Low,
                Category::DataValidation,
                0.5,
                &format!("Unused Parameters in {}", function.name),
                &format!("Function '{}' has unused parameters: {}.", function.name, unused_params.join(", ")),
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Remove or use unused parameters.",
            ));
        }

        
        // --- Advanced: Unprotected Initializer Detection ---
        let mut has_require_or_assert_or_revert = false;
        fn walk_for_require_assert_revert(stmts: &[SwayStatement], found: &mut bool) {
            use crate::parser::StatementKind::*;
            for stmt in stmts {
                match &stmt.kind {
                    Require(_) => {
                        *found = true;
                    }
                    Assert(_) => {
                        *found = true;
                    }
                    Expression(expr) => {
                        if format!("{}", expr).contains("revert") {
                            *found = true;
                        }
                    }
                    If(if_stmt) => {
                        walk_for_require_assert_revert(&if_stmt.then_block, found);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_require_assert_revert(else_block, found);
                        }
                    }
                    While(while_stmt) => walk_for_require_assert_revert(&while_stmt.body, found),
                    For(for_stmt) => walk_for_require_assert_revert(&for_stmt.body, found),
                    Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_require_assert_revert(&arm.body, found);
                        }
                    }
                    Block(stmts) => walk_for_require_assert_revert(stmts, found),
                    _ => {}
                }
            }
        }
        walk_for_require_assert_revert(&function.body, &mut has_require_or_assert_or_revert);
        if function.name.to_lowercase().contains("init") && !has_require_or_assert_or_revert {
            findings.push(Finding::new(
                "data_validation",
                Severity::Low,
                Category::DataValidation,
                0.5,
                &format!("Unprotected Initializer - {}", function.name),
                "Initializer function is not protected by a require/assert/revert. Consider restricting access.",
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Add a require/assert/revert to restrict who can call the initializer.",
            ));
        }

        // --- Advanced: Unprotected Storage Write Detection ---
        let mut has_msg_sender_check = false;
        fn walk_for_msg_sender(stmts: &[SwayStatement], found: &mut bool) {
            use crate::parser::StatementKind::*;
            for stmt in stmts {
                match &stmt.kind {
                    Require(req) => {
                        if format!("{}", req.condition).contains("msg_sender") {
                            *found = true;
                        }
                    }
                    Assert(assert) => {
                        if format!("{}", assert.condition).contains("msg_sender") {
                            *found = true;
                        }
                    }
                    Expression(expr) => {
                        if format!("{}", expr).contains("msg_sender") {
                            *found = true;
                        }
                    }
                    If(if_stmt) => {
                        walk_for_msg_sender(&if_stmt.then_block, found);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_msg_sender(else_block, found);
                        }
                    }
                    While(while_stmt) => walk_for_msg_sender(&while_stmt.body, found),
                    For(for_stmt) => walk_for_msg_sender(&for_stmt.body, found),
                    Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_msg_sender(&arm.body, found);
                        }
                    }
                    Block(stmts) => walk_for_msg_sender(stmts, found),
                    _ => {}
                }
            }
        }
        walk_for_msg_sender(&function.body, &mut has_msg_sender_check);
        if !function.storage_writes.is_empty() && !has_msg_sender_check {
            findings.push(Finding::new(
                "data_validation",
                Severity::Low,
                Category::DataValidation,
                0.5,
                &format!("Unprotected Storage Write - {}", function.name),
                "Function writes to storage without checking msg_sender(). Consider restricting access.",
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Add a require/assert to restrict storage writes to authorized callers.",
            ));
        }

        if findings.is_empty() {
            None
        } else {
            // Return all findings for this function
            Some(Finding::new(
                "data_validation",
                findings.iter().map(|f| f.severity.clone()).max().unwrap_or(Severity::Low),
                Category::DataValidation,
                findings.iter().map(|f| f.confidence).fold(0.0, |a, b| a.max(b)),
                &format!("Data Validation Issues - {}", function.name),
                &findings.iter().map(|f| f.description.clone()).collect::<Vec<_>>().join("\n"),
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                &findings.iter().map(|f| f.recommendation.clone()).collect::<Vec<_>>().join("\n"),
            ))
        }
    }
}

impl Detector for DataValidationDetector {
    fn name(&self) -> &'static str {
        "data_validation"
    }
    fn description(&self) -> &'static str {
        "Detects data validation issues using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::DataValidation
    }
    fn default_severity(&self) -> Severity {
        Severity::Medium
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_data_validation(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 