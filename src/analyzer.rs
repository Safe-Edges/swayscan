use crate::parser::{SwayFile, SwayAst, SwayFunction, SwayStatement, SwayExpression, SwayStorageField, 
                   SwayParameter, SwayType, StatementKind, ExpressionKind, FunctionVisibility, Span};
use crate::detectors::AnalysisContext;
use std::collections::{HashMap, HashSet};

/// AST-based analyzer for Sway smart contracts
pub struct SwayAstAnalyzer {
    pub function_call_graph: FunctionCallGraph,
    pub storage_analysis: StorageAnalysis,
    pub control_flow_analysis: ControlFlowAnalysis,
    pub security_analysis: SecurityAnalysis,
}

/// Function Call Graph - Maps callers and callees with AST context
#[derive(Debug, Clone)]
pub struct FunctionCallGraph {
    pub functions: HashMap<String, SwayFunction>,
    pub call_relationships: HashMap<String, Vec<String>>, // caller -> callees
    pub reverse_calls: HashMap<String, Vec<String>>,     // callee -> callers
    pub function_spans: HashMap<String, Span>,
}

/// Storage Analysis - Tracks storage operations using AST
#[derive(Debug, Clone)]
pub struct StorageAnalysis {
    pub storage_fields: HashMap<String, StorageFieldInfo>,
    pub read_operations: HashMap<String, Vec<StorageRead>>,
    pub write_operations: HashMap<String, Vec<StorageWrite>>,
    pub storage_dependencies: HashMap<String, Vec<String>>,
}

/// Control Flow Analysis - Analyzes control flow using AST
#[derive(Debug, Clone)]
pub struct ControlFlowAnalysis {
    pub control_flow_graph: HashMap<String, Vec<ControlFlowNode>>,
    pub conditional_branches: HashMap<String, Vec<ConditionalBranch>>,
    pub loop_structures: HashMap<String, Vec<LoopStructure>>,
    pub exception_handling: HashMap<String, Vec<ExceptionHandler>>,
}

/// Security Analysis - Performs security analysis using AST
#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub access_control_checks: HashMap<String, Vec<AccessControlCheck>>,
    pub reentrancy_vulnerabilities: HashMap<String, Vec<ReentrancyVulnerability>>,
    pub external_call_analysis: HashMap<String, Vec<ExternalCallAnalysis>>,
    pub arithmetic_analysis: HashMap<String, Vec<ArithmeticAnalysis>>,
}

#[derive(Debug, Clone)]
pub struct StorageFieldInfo {
    pub name: String,
    pub type_: String,
    pub span: Span,
    pub is_public: bool,
    pub access_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StorageRead {
    pub field: String,
    pub function: String,
    pub span: Span,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct StorageWrite {
    pub field: String,
    pub function: String,
    pub span: Span,
    pub context: String,
    pub access_control: Option<AccessControlCheck>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowNode {
    pub node_id: String,
    pub statement: SwayStatement,
    pub successors: Vec<String>,
    pub predecessors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConditionalBranch {
    pub condition: SwayExpression,
    pub then_branch: Vec<SwayStatement>,
    pub else_branch: Option<Vec<SwayStatement>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct LoopStructure {
    pub loop_type: LoopType,
    pub condition: SwayExpression,
    pub body: Vec<SwayStatement>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum LoopType {
    While,
    For,
    Loop,
}

#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub handler_type: ExceptionType,
    pub body: Vec<SwayStatement>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ExceptionType {
    Require,
    Assert,
    Revert,
}

#[derive(Debug, Clone)]
pub struct AccessControlCheck {
    pub check_type: AccessControlType,
    pub condition: SwayExpression,
    pub function: String,
    pub span: Span,
    pub is_effective: bool,
}

#[derive(Debug, Clone)]
pub enum AccessControlType {
    OwnerCheck,
    RoleCheck,
    PermissionCheck,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct ReentrancyVulnerability {
    pub function: String,
    pub external_call: SwayExpression,
    pub state_change: SwayExpression,
    pub span: Span,
    pub severity: ReentrancySeverity,
}

#[derive(Debug, Clone)]
pub enum ReentrancySeverity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct ExternalCallAnalysis {
    pub function: String,
    pub call: SwayExpression,
    pub span: Span,
    pub is_checked: bool,
    pub return_value_handled: bool,
}

#[derive(Debug, Clone)]
pub struct ArithmeticAnalysis {
    pub operation: String,
    pub operands: Vec<SwayExpression>,
    pub span: Span,
    pub overflow_risk: bool,
    pub underflow_risk: bool,
}

impl SwayAstAnalyzer {
    pub fn new() -> Self {
        Self {
            function_call_graph: FunctionCallGraph::new(),
            storage_analysis: StorageAnalysis::new(),
            control_flow_analysis: ControlFlowAnalysis::new(),
            security_analysis: SecurityAnalysis::new(),
        }
    }

    /// Main analysis entry point using Sway AST
    pub fn analyze_file(&mut self, file: &SwayFile) -> AnalysisContext {
        if let Some(ast) = &file.ast {
            // Phase 1: Build Function Call Graph from AST
            self.function_call_graph.build_from_ast(ast);
            
            // Phase 2: Analyze Storage Operations using AST
            self.storage_analysis.analyze_from_ast(ast);
            
            // Phase 3: Analyze Control Flow using AST
            self.control_flow_analysis.analyze_from_ast(ast);
            
            // Phase 4: Perform Security Analysis using AST
            self.security_analysis.analyze_from_ast(ast);
            
            // Return enriched context
            AnalysisContext {
                function_name: None,
                contract_type: Some("sway_contract".to_string()),
                dependencies: self.extract_dependencies(ast),
                complexity_score: Some(self.calculate_complexity(ast)),
                call_depth: Some(self.calculate_max_call_depth()),
                variables_in_scope: self.extract_variables_in_scope(ast),
            }
        } else {
            // Fallback for files without AST
        AnalysisContext {
            function_name: None,
            contract_type: None,
            dependencies: Vec::new(),
            complexity_score: None,
            call_depth: None,
            variables_in_scope: Vec::new(),
            }
        }
    }

    fn extract_dependencies(&self, ast: &SwayAst) -> Vec<String> {
        let mut dependencies = Vec::new();
        
        // Extract imports
        for import in &ast.imports {
            dependencies.push(import.module.clone());
        }
        
        // Extract trait dependencies
        for trait_ in &ast.traits {
            dependencies.push(format!("trait:{}", trait_.name));
        }
        
        dependencies
    }

    fn calculate_complexity(&self, ast: &SwayAst) -> u32 {
        let mut complexity = 0;
        
        for function in &ast.functions {
            complexity += self.calculate_function_complexity(function);
        }
        
        complexity
    }

    fn calculate_function_complexity(&self, function: &SwayFunction) -> u32 {
        let mut complexity = 1; // Base complexity
        
        for statement in &function.body {
            complexity += self.calculate_statement_complexity(statement);
        }
        
        complexity
    }

    fn calculate_statement_complexity(&self, statement: &SwayStatement) -> u32 {
        match &statement.kind {
            StatementKind::If(_) => 2,
            StatementKind::While(_) => 3,
            StatementKind::For(_) => 3,
            StatementKind::Match(_) => 2,
            StatementKind::Block(statements) => {
                statements.iter().map(|s| self.calculate_statement_complexity(s)).sum()
            }
            _ => 1,
        }
    }

    fn calculate_max_call_depth(&self) -> u32 {
        let mut max_depth = 0;
        
        for (function_name, _) in &self.function_call_graph.functions {
            let depth = self.calculate_call_depth_recursive(function_name, &mut HashSet::new());
            max_depth = max_depth.max(depth);
        }
        
        max_depth
    }

    fn calculate_call_depth_recursive(&self, function_name: &str, visited: &mut HashSet<String>) -> u32 {
        if visited.contains(function_name) {
            return 0; // Prevent infinite recursion
        }
        
        visited.insert(function_name.to_string());
        
        if let Some(callees) = self.function_call_graph.call_relationships.get(function_name) {
            let mut max_depth = 0;
            for callee in callees {
                let depth = 1 + self.calculate_call_depth_recursive(callee, visited);
                max_depth = max_depth.max(depth);
            }
            max_depth
        } else {
            0
        }
    }

    fn extract_variables_in_scope(&self, ast: &SwayAst) -> Vec<String> {
        let mut variables = Vec::new();
        
        for function in &ast.functions {
            for parameter in &function.parameters {
                variables.push(parameter.name.clone());
            }
        }
        
        variables
    }

    /// Check if a function has proper access control using AST analysis
    pub fn has_access_control(&self, function_name: &str) -> bool {
        // Find the function in our analyzed functions
        if let Some(function) = self.function_call_graph.functions.get(function_name) {
            // Check if function has require statements (access control checks)
            if !function.require_statements.is_empty() {
                return true;
            }
            
            // Check for common access control patterns in function content
            let content = self.get_function_content(function);
            
            // Look for access control patterns
            let access_control_patterns = [
                "msg_sender().unwrap() == storage.owner.read()",
                "msg_sender().unwrap() == storage.owner",
                "require(msg_sender().unwrap() == storage.owner",
                "msg_sender() == storage.owner",
                "msg_sender().unwrap() == owner",
                "require(msg_sender().unwrap() == owner",
                "only_owner",
                "only_admin",
                "require(msg_sender().unwrap() == admin",
                "msg_sender().unwrap() == admin",
            ];
            
            for pattern in &access_control_patterns {
                if content.contains(pattern) {
                    return true;
                }
            }
        }
        
        false
    }

    fn get_function_content(&self, function: &SwayFunction) -> String {
        function.content.clone()
    }

    /// Check for reentrancy vulnerabilities using AST analysis
    pub fn has_reentrancy_vulnerability(&self, function_name: &str) -> bool {
        if let Some(vulnerabilities) = self.security_analysis.reentrancy_vulnerabilities.get(function_name) {
            !vulnerabilities.is_empty()
        } else {
            false
        }
    }

    /// Check for unchecked external calls using AST analysis
    pub fn has_unchecked_external_call(&self, function_name: &str) -> bool {
        if let Some(calls) = self.security_analysis.external_call_analysis.get(function_name) {
            calls.iter().any(|call| !call.is_checked)
                        } else {
            false
        }
    }

    /// Get all storage operations for a function using AST analysis
    pub fn get_storage_operations(&self, function_name: &str) -> (Vec<String>, Vec<String>) {
        let reads = self.storage_analysis.read_operations
            .get(function_name)
            .map(|reads| reads.iter().map(|r| r.field.clone()).collect())
            .unwrap_or_default();
            
        let writes = self.storage_analysis.write_operations
            .get(function_name)
            .map(|writes| writes.iter().map(|w| w.field.clone()).collect())
            .unwrap_or_default();
            
        (reads, writes)
    }
}

impl FunctionCallGraph {
    fn new() -> Self {
        Self {
            functions: HashMap::new(),
            call_relationships: HashMap::new(),
            reverse_calls: HashMap::new(),
            function_spans: HashMap::new(),
        }
    }

    fn build_from_ast(&mut self, ast: &SwayAst) {
        // Extract all functions
        for function in &ast.functions {
            self.functions.insert(function.name.clone(), function.clone());
            self.function_spans.insert(function.name.clone(), function.span.clone());
        }
        
        // Build call relationships by analyzing function bodies
        for function in &ast.functions {
            let mut callees = Vec::new();
            self.extract_function_calls(function, &mut callees);
            
            if !callees.is_empty() {
                self.call_relationships.insert(function.name.clone(), callees.clone());
                
                // Build reverse calls
                for callee in callees {
                    self.reverse_calls.entry(callee).or_insert_with(Vec::new).push(function.name.clone());
                }
            }
        }
    }

    fn extract_function_calls(&self, function: &SwayFunction, callees: &mut Vec<String>) {
        for statement in &function.body {
            self.extract_calls_from_statement(statement, callees);
        }
    }

    fn extract_calls_from_statement(&self, statement: &SwayStatement, callees: &mut Vec<String>) {
        match &statement.kind {
            StatementKind::Expression(expr) => {
                self.extract_calls_from_expression(expr, callees);
            }
            StatementKind::Block(statements) => {
                for stmt in statements {
                    self.extract_calls_from_statement(stmt, callees);
                }
            }
            StatementKind::If(if_stmt) => {
                for stmt in &if_stmt.then_block {
                    self.extract_calls_from_statement(stmt, callees);
                }
                if let Some(else_block) = &if_stmt.else_block {
                    for stmt in else_block {
                        self.extract_calls_from_statement(stmt, callees);
                    }
                }
            }
            StatementKind::While(while_stmt) => {
                for stmt in &while_stmt.body {
                    self.extract_calls_from_statement(stmt, callees);
                }
            }
            StatementKind::For(for_stmt) => {
                for stmt in &for_stmt.body {
                    self.extract_calls_from_statement(stmt, callees);
                }
            }
            _ => {}
        }
    }

    fn extract_calls_from_expression(&self, expr: &SwayExpression, callees: &mut Vec<String>) {
        match &expr.kind {
            ExpressionKind::FunctionCall(call) => {
                callees.push(call.function.clone());
            }
            ExpressionKind::MethodCall(call) => {
                // Extract method calls as well
                callees.push(format!("{}.{}", "receiver", call.method));
            }
            ExpressionKind::Binary(binary) => {
                self.extract_calls_from_expression(&binary.left, callees);
                self.extract_calls_from_expression(&binary.right, callees);
            }
            ExpressionKind::Unary(unary) => {
                self.extract_calls_from_expression(&unary.operand, callees);
            }
            ExpressionKind::If(if_expr) => {
                self.extract_calls_from_expression(&if_expr.then_expr, callees);
                if let Some(else_expr) = &if_expr.else_expr {
                    self.extract_calls_from_expression(else_expr, callees);
                }
            }
            _ => {}
        }
    }
}

impl StorageAnalysis {
    fn new() -> Self {
        Self {
            storage_fields: HashMap::new(),
            read_operations: HashMap::new(),
            write_operations: HashMap::new(),
            storage_dependencies: HashMap::new(),
        }
    }

    fn analyze_from_ast(&mut self, ast: &SwayAst) {
        // Extract storage fields
        for field in &ast.storage_fields {
            self.storage_fields.insert(field.name.clone(), StorageFieldInfo {
                name: field.name.clone(),
                type_: field.type_.name.clone(),
                span: field.span.clone(),
                is_public: false, // Would need to check visibility
                access_patterns: Vec::new(),
            });
        }
        
        // Analyze storage operations in functions
        for function in &ast.functions {
            self.analyze_function_storage_operations(function);
        }
    }

    fn analyze_function_storage_operations(&mut self, function: &SwayFunction) {
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        
        for statement in &function.body {
            self.extract_storage_operations_from_statement(statement, &mut reads, &mut writes);
        }
        
        if !reads.is_empty() {
            self.read_operations.insert(function.name.clone(), reads);
        }
        
        if !writes.is_empty() {
            self.write_operations.insert(function.name.clone(), writes);
        }
    }

    fn extract_storage_operations_from_statement(
        &self,
        statement: &SwayStatement,
        reads: &mut Vec<StorageRead>,
        writes: &mut Vec<StorageWrite>,
    ) {
        match &statement.kind {
            StatementKind::Storage(storage_stmt) => {
                let operation = StorageRead {
                    field: storage_stmt.field.clone(),
                    function: "unknown".to_string(),
                    span: statement.span.clone(),
                    context: "storage_operation".to_string(),
                };
                
                match storage_stmt.operation {
                    crate::parser::StorageOperation::Read => {
                        reads.push(operation);
                    }
                    crate::parser::StorageOperation::Write => {
                        writes.push(StorageWrite {
                            field: storage_stmt.field.clone(),
                            function: "unknown".to_string(),
                            span: statement.span.clone(),
                            context: "storage_operation".to_string(),
                            access_control: None,
                        });
                    }
                    crate::parser::StorageOperation::Both => {
                        reads.push(operation);
                        writes.push(StorageWrite {
                            field: storage_stmt.field.clone(),
                            function: "unknown".to_string(),
                            span: statement.span.clone(),
                            context: "storage_operation".to_string(),
                            access_control: None,
                        });
                    }
                }
            }
            StatementKind::Expression(expr) => {
                self.extract_storage_operations_from_expression(expr, reads, writes);
            }
            StatementKind::Block(statements) => {
                for stmt in statements {
                    self.extract_storage_operations_from_statement(stmt, reads, writes);
                }
            }
            _ => {}
        }
    }

    fn extract_storage_operations_from_expression(
        &self,
        expr: &SwayExpression,
        reads: &mut Vec<StorageRead>,
        writes: &mut Vec<StorageWrite>,
    ) {
        match &expr.kind {
            ExpressionKind::MethodCall(call) => {
                if call.method == "read" {
                    if let ExpressionKind::Variable(field) = &call.receiver.kind {
                        reads.push(StorageRead {
                            field: field.clone(),
                            function: "unknown".to_string(),
                            span: expr.span.clone(),
                            context: "method_call".to_string(),
                        });
                    }
                } else if call.method == "write" {
                    if let ExpressionKind::Variable(field) = &call.receiver.kind {
                        writes.push(StorageWrite {
                            field: field.clone(),
                            function: "unknown".to_string(),
                            span: expr.span.clone(),
                            context: "method_call".to_string(),
                            access_control: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

impl ControlFlowAnalysis {
    fn new() -> Self {
        Self {
            control_flow_graph: HashMap::new(),
            conditional_branches: HashMap::new(),
            loop_structures: HashMap::new(),
            exception_handling: HashMap::new(),
        }
    }

    fn analyze_from_ast(&mut self, ast: &SwayAst) {
        for function in &ast.functions {
            self.analyze_function_control_flow(function);
        }
    }

    fn analyze_function_control_flow(&mut self, function: &SwayFunction) {
        let mut control_flow_nodes = Vec::new();
        let mut conditional_branches = Vec::new();
        let mut loop_structures = Vec::new();
        let mut exception_handlers = Vec::new();
        
        for statement in &function.body {
            self.analyze_statement_control_flow(
                statement,
                &mut control_flow_nodes,
                &mut conditional_branches,
                &mut loop_structures,
                &mut exception_handlers,
            );
        }
        
        if !control_flow_nodes.is_empty() {
            self.control_flow_graph.insert(function.name.clone(), control_flow_nodes);
        }
        
        if !conditional_branches.is_empty() {
            self.conditional_branches.insert(function.name.clone(), conditional_branches);
        }
        
        if !loop_structures.is_empty() {
            self.loop_structures.insert(function.name.clone(), loop_structures);
        }
        
        if !exception_handlers.is_empty() {
            self.exception_handling.insert(function.name.clone(), exception_handlers);
        }
    }

    fn analyze_statement_control_flow(
        &self,
        statement: &SwayStatement,
        control_flow_nodes: &mut Vec<ControlFlowNode>,
        conditional_branches: &mut Vec<ConditionalBranch>,
        loop_structures: &mut Vec<LoopStructure>,
        exception_handlers: &mut Vec<ExceptionHandler>,
    ) {
        match &statement.kind {
            StatementKind::If(if_stmt) => {
                conditional_branches.push(ConditionalBranch {
                    condition: *if_stmt.condition.clone(),
                    then_branch: if_stmt.then_block.clone(),
                    else_branch: if_stmt.else_block.clone(),
                    span: statement.span.clone(),
                });
            }
            StatementKind::While(while_stmt) => {
                loop_structures.push(LoopStructure {
                    loop_type: LoopType::While,
                    condition: *while_stmt.condition.clone(),
                    body: while_stmt.body.clone(),
                    span: statement.span.clone(),
                });
            }
            StatementKind::For(for_stmt) => {
                loop_structures.push(LoopStructure {
                    loop_type: LoopType::For,
                    condition: SwayExpression {
                        kind: ExpressionKind::Variable("iterator".to_string()),
                        span: statement.span.clone(),
                    },
                    body: for_stmt.body.clone(),
                    span: statement.span.clone(),
                });
            }
            StatementKind::Require(require_stmt) => {
                exception_handlers.push(ExceptionHandler {
                    handler_type: ExceptionType::Require,
                    body: Vec::new(),
                    span: statement.span.clone(),
                });
            }
            StatementKind::Assert(assert_stmt) => {
                exception_handlers.push(ExceptionHandler {
                    handler_type: ExceptionType::Assert,
                    body: Vec::new(),
                    span: statement.span.clone(),
                });
            }
            _ => {}
        }
    }
}

impl SecurityAnalysis {
    fn new() -> Self {
        Self {
            access_control_checks: HashMap::new(),
            reentrancy_vulnerabilities: HashMap::new(),
            external_call_analysis: HashMap::new(),
            arithmetic_analysis: HashMap::new(),
        }
    }

    fn analyze_from_ast(&mut self, ast: &SwayAst) {
        for function in &ast.functions {
            self.analyze_function_security(function);
        }
    }

    fn analyze_function_security(&mut self, function: &SwayFunction) {
        let mut access_controls = Vec::new();
        let mut reentrancy_vulns = Vec::new();
        let mut external_calls = Vec::new();
        let mut arithmetic_ops = Vec::new();
        
        for statement in &function.body {
            self.analyze_statement_security(
                statement,
                function,
                &mut access_controls,
                &mut reentrancy_vulns,
                &mut external_calls,
                &mut arithmetic_ops,
            );
        }
        
        if !access_controls.is_empty() {
            self.access_control_checks.insert(function.name.clone(), access_controls);
        }
        
        if !reentrancy_vulns.is_empty() {
            self.reentrancy_vulnerabilities.insert(function.name.clone(), reentrancy_vulns);
        }
        
        if !external_calls.is_empty() {
            self.external_call_analysis.insert(function.name.clone(), external_calls);
        }
        
        if !arithmetic_ops.is_empty() {
            self.arithmetic_analysis.insert(function.name.clone(), arithmetic_ops);
        }
    }

    fn analyze_statement_security(
        &self,
        statement: &SwayStatement,
        function: &SwayFunction,
        access_controls: &mut Vec<AccessControlCheck>,
        reentrancy_vulns: &mut Vec<ReentrancyVulnerability>,
        external_calls: &mut Vec<ExternalCallAnalysis>,
        arithmetic_ops: &mut Vec<ArithmeticAnalysis>,
    ) {
        match &statement.kind {
            StatementKind::Require(require_stmt) => {
                access_controls.push(AccessControlCheck {
                    check_type: AccessControlType::Custom("require".to_string()),
                    condition: *require_stmt.condition.clone(),
                    function: function.name.clone(),
                    span: statement.span.clone(),
                    is_effective: true,
                });
            }
            StatementKind::Expression(expr) => {
                self.analyze_expression_security(
                    expr,
                    function,
                    access_controls,
                    reentrancy_vulns,
                    external_calls,
                    arithmetic_ops,
                );
            }
            StatementKind::Block(statements) => {
                for stmt in statements {
                    self.analyze_statement_security(
                        stmt,
                        function,
                        access_controls,
                        reentrancy_vulns,
                        external_calls,
                        arithmetic_ops,
                    );
                }
            }
            _ => {}
        }
    }

    fn analyze_expression_security(
        &self,
        expr: &SwayExpression,
        function: &SwayFunction,
        access_controls: &mut Vec<AccessControlCheck>,
        reentrancy_vulns: &mut Vec<ReentrancyVulnerability>,
        external_calls: &mut Vec<ExternalCallAnalysis>,
        arithmetic_ops: &mut Vec<ArithmeticAnalysis>,
    ) {
        match &expr.kind {
            ExpressionKind::FunctionCall(call) => {
                // Check for external calls
                if self.is_external_call(&call.function) {
                    external_calls.push(ExternalCallAnalysis {
                        function: function.name.clone(),
                        call: expr.clone(),
                        span: expr.span.clone(),
                        is_checked: false, // Would need deeper analysis
                        return_value_handled: false,
                    });
                }
            }
            ExpressionKind::Binary(binary) => {
                // Check for arithmetic operations
                if self.is_arithmetic_operation(&binary.operator) {
                    arithmetic_ops.push(ArithmeticAnalysis {
                        operation: binary.operator.clone(),
                        operands: vec![*binary.left.clone(), *binary.right.clone()],
                        span: expr.span.clone(),
                        overflow_risk: self.has_overflow_risk(&binary.operator),
                        underflow_risk: self.has_underflow_risk(&binary.operator),
                    });
                }
            }
            _ => {}
        }
    }

    fn is_external_call(&self, function: &str) -> bool {
        let external_functions = [
            "transfer", "mint", "burn", "force_transfer", "mint_to", "burn_from",
            "call", "delegatecall", "staticcall", "create", "create2"
        ];
        
        external_functions.iter().any(|&f| function.contains(f))
    }

    fn is_arithmetic_operation(&self, operator: &str) -> bool {
        matches!(operator, "+" | "-" | "*" | "/" | "%" | "**")
    }

    fn has_overflow_risk(&self, operator: &str) -> bool {
        matches!(operator, "+" | "*" | "**")
    }

    fn has_underflow_risk(&self, operator: &str) -> bool {
        matches!(operator, "-")
    }
} 