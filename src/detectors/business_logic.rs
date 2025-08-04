use crate::detectors::{Detector, Finding, Severity, Category, AnalysisContext};
use crate::error::SwayscanError;
use crate::parser::{SwayFile, SwayAst, SwayFunction};

pub struct BusinessLogicDetector;

impl BusinessLogicDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_function_business_logic(&self, function: &SwayFunction, file: &SwayFile, ast: &SwayAst) -> Option<Finding> {
        use crate::parser::{StatementKind, ExpressionKind, SwayStatement, SwayExpression};
        // State for tracking business logic issues
        struct BizState {
            balance_written: bool,
            supply_written: bool,
            cap_written: bool,
            owner_written: bool,
            has_validation: bool,
            has_balance_check: bool,
            has_supply_check: bool,
            has_deadline_check: bool,
            found_issue: Option<String>,
        }
        fn walk_for_biz_issues(stmts: &[SwayStatement], state: &mut BizState) {
            for stmt in stmts {
                match &stmt.kind {
                    StatementKind::Storage(storage_stmt) => {
                        match storage_stmt.field.as_str() {
                            "balance" => state.balance_written = true,
                            "total_supply" | "supply" => state.supply_written = true,
                            "cap" => state.cap_written = true,
                            "owner" => state.owner_written = true,
                            _ => {}
                        }
                    }
                    StatementKind::Expression(expr) => {
                        walk_expr_for_biz_issues(expr, state);
                    }
                    StatementKind::Require(_) | StatementKind::Assert(_) => {
                        state.has_validation = true;
                    }
                    StatementKind::If(if_stmt) => {
                        walk_for_biz_issues(&if_stmt.then_block, state);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_biz_issues(else_block, state);
                        }
                    }
                    StatementKind::While(while_stmt) => walk_for_biz_issues(&while_stmt.body, state),
                    StatementKind::For(for_stmt) => walk_for_biz_issues(&for_stmt.body, state),
                    StatementKind::Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_biz_issues(&arm.body, state);
                        }
                    }
                    StatementKind::Block(stmts) => walk_for_biz_issues(stmts, state),
                    _ => {}
                }
            }
        }
        fn walk_expr_for_biz_issues(expr: &SwayExpression, state: &mut BizState) {
            use ExpressionKind::*;
            match &expr.kind {
                FunctionCall(call) => {
                    // Detect transfer, mint, burn, withdraw, etc.
                    let func = call.function.as_str();
                    if func == "transfer" {
                        state.found_issue.get_or_insert("transfer".to_string());
                    } else if func == "mint" {
                        state.found_issue.get_or_insert("mint".to_string());
                    } else if func == "burn" {
                        state.found_issue.get_or_insert("burn".to_string());
                    } else if func == "withdraw" {
                        state.found_issue.get_or_insert("withdraw".to_string());
                    }
                    for arg in &call.arguments {
                        walk_expr_for_biz_issues(arg, state);
                    }
                }
                MethodCall(mc) => {
                    walk_expr_for_biz_issues(&mc.receiver, state);
                    for arg in &mc.arguments {
                        walk_expr_for_biz_issues(arg, state);
                    }
                }
                Binary(bin) => {
                    walk_expr_for_biz_issues(&bin.left, state);
                    walk_expr_for_biz_issues(&bin.right, state);
                }
                Unary(u) => walk_expr_for_biz_issues(&u.operand, state),
                If(if_expr) => {
                    walk_expr_for_biz_issues(&if_expr.condition, state);
                    walk_expr_for_biz_issues(&if_expr.then_expr, state);
                    if let Some(else_expr) = &if_expr.else_expr {
                        walk_expr_for_biz_issues(else_expr, state);
                    }
                }
                Match(match_expr) => {
                    walk_expr_for_biz_issues(&match_expr.expression, state);
                    for arm in &match_expr.arms {
                        for stmt in &arm.body {
                            if let StatementKind::Expression(e) = &stmt.kind {
                                walk_expr_for_biz_issues(e, state);
                            }
                        }
                    }
                }
                Block(stmts) => walk_for_biz_issues(stmts, state),
                Array(arr) | Tuple(arr) => {
                    for e in arr {
                        walk_expr_for_biz_issues(e, state);
                    }
                }
                Struct(se) => {
                    for f in &se.fields {
                        walk_expr_for_biz_issues(&f.value, state);
                    }
                }
                Index(idx) => {
                    walk_expr_for_biz_issues(&idx.array, state);
                    walk_expr_for_biz_issues(&idx.index, state);
                }
                Field(fe) => walk_expr_for_biz_issues(&fe.receiver, state),
                Parenthesized(e) => walk_expr_for_biz_issues(e, state),
                _ => {}
            }
        }
        // --- Manipulatable Balance Usage Detection ---
        // Track storage fields named 'balance'
        let mut balance_fields = vec![];
        for field in &ast.storage_fields {
            if field.name.to_lowercase().contains("balance") {
                balance_fields.push(field.name.clone());
            }
        }
        // Track if balance is used in arithmetic and then in a transfer
        let mut balance_used_in_arith = false;
        let mut transfer_uses_balance = false;
        fn walk_for_balance_arith(stmts: &[SwayStatement], balance_fields: &[String], used_in_arith: &mut bool, used_in_transfer: &mut bool) {
            use crate::parser::StatementKind::*;
            for stmt in stmts {
                match &stmt.kind {
                    Expression(expr) => {
                        walk_expr_for_balance_arith(expr, balance_fields, used_in_arith, used_in_transfer);
                    }
                    If(if_stmt) => {
                        walk_for_balance_arith(&if_stmt.then_block, balance_fields, used_in_arith, used_in_transfer);
                        if let Some(else_block) = &if_stmt.else_block {
                            walk_for_balance_arith(else_block, balance_fields, used_in_arith, used_in_transfer);
                        }
                    }
                    While(while_stmt) => walk_for_balance_arith(&while_stmt.body, balance_fields, used_in_arith, used_in_transfer),
                    For(for_stmt) => walk_for_balance_arith(&for_stmt.body, balance_fields, used_in_arith, used_in_transfer),
                    Match(match_stmt) => {
                        for arm in &match_stmt.arms {
                            walk_for_balance_arith(&arm.body, balance_fields, used_in_arith, used_in_transfer);
                        }
                    }
                    Block(stmts) => walk_for_balance_arith(stmts, balance_fields, used_in_arith, used_in_transfer),
                    _ => {}
                }
            }
        }
        fn walk_expr_for_balance_arith(expr: &SwayExpression, balance_fields: &[String], used_in_arith: &mut bool, used_in_transfer: &mut bool) {
            use ExpressionKind::*;
            match &expr.kind {
                Binary(bin) => {
                    let left = format!("{}", bin.left);
                    let right = format!("{}", bin.right);
                    if balance_fields.iter().any(|b| left.contains(b) || right.contains(b)) {
                        *used_in_arith = true;
                    }
                    walk_expr_for_balance_arith(&bin.left, balance_fields, used_in_arith, used_in_transfer);
                    walk_expr_for_balance_arith(&bin.right, balance_fields, used_in_arith, used_in_transfer);
                }
                FunctionCall(call) => {
                    let func = call.function.as_str();
                    if ["transfer", "transfer_to_address", "force_transfer_to_contract", "call_with_function_selector"].contains(&func) {
                        for arg in &call.arguments {
                            let arg_str = format!("{}", arg);
                            if balance_fields.iter().any(|b| arg_str.contains(b)) {
                                *used_in_transfer = true;
                            }
                        }
                    }
                    for arg in &call.arguments {
                        walk_expr_for_balance_arith(arg, balance_fields, used_in_arith, used_in_transfer);
                    }
                }
                MethodCall(mc) => {
                    walk_expr_for_balance_arith(&mc.receiver, balance_fields, used_in_arith, used_in_transfer);
                    for arg in &mc.arguments {
                        walk_expr_for_balance_arith(arg, balance_fields, used_in_arith, used_in_transfer);
                    }
                }
                _ => {}
            }
        }
        walk_for_balance_arith(&function.body, &balance_fields, &mut balance_used_in_arith, &mut transfer_uses_balance);
        if balance_used_in_arith && transfer_uses_balance {
            let description = format!("Function '{}' contains manipulatable balance usage: balance is used in arithmetic and then in a transfer operation.", function.name);
            return Some(Finding::new(
                "business_logic",
                Severity::Medium,
                Category::BusinessLogic,
                0.8,
                &format!("Manipulatable Balance Usage - {}", function.name),
                &description,
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Avoid using balances in arithmetic before transfers to prevent manipulation.",
            ));
        }
        // Analyze function
        let mut state = BizState {
            balance_written: false,
            supply_written: false,
            cap_written: false,
            owner_written: false,
            has_validation: false,
            has_balance_check: false,
            has_supply_check: false,
            has_deadline_check: false,
            found_issue: None,
        };
        walk_for_biz_issues(&function.body, &mut state);
        // Only flag if a critical operation is performed without the necessary business check
        if let Some(issue) = &state.found_issue {
            let mut description = format!("Function '{}' contains potential business logic vulnerability ({}).", function.name, issue);
            if !state.has_validation {
                description.push_str(" No validation detected.");
            }
            if !state.has_balance_check && issue == "transfer" {
                description.push_str(" No balance check detected.");
            }
            if !state.has_supply_check && issue == "mint" {
                description.push_str(" No supply cap check detected.");
            }
            // ... add more Sway-specific checks as needed
            return Some(Finding::new(
                "business_logic",
                Severity::High,
                Category::BusinessLogic,
                0.9,
                &format!("Business Logic Vulnerability Detected - {}", function.name),
                &description,
                &file.path,
                function.span.start,
                function.span.start,
                &function.content,
                "Implement proper business rule validation, balance checks, supply caps, and deadline validation.",
            ));
        }
        None
    }
}

impl Detector for BusinessLogicDetector {
    fn name(&self) -> &'static str {
        "business_logic"
    }
    fn description(&self) -> &'static str {
        "Detects business logic vulnerabilities using advanced AST-based analysis."
    }
    fn category(&self) -> Category {
        Category::BusinessLogic
    }
    fn default_severity(&self) -> Severity {
        Severity::High
    }
    fn analyze(&self, file: &SwayFile, _context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError> {
        let mut findings = Vec::new();
        if let Some(ast) = &file.ast {
            for function in &ast.functions {
                if let Some(finding) = self.analyze_function_business_logic(function, file, ast) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
} 