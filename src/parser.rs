use crate::error::SwayscanError;
use std::path::Path;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SwayFile {
    pub path: String,
    pub content: String,
    pub ast: Option<SwayAst>,
}

#[derive(Debug, Clone)]
pub struct SwayAst {
    pub functions: Vec<SwayFunction>,
    pub storage_fields: Vec<SwayStorageField>,
    pub imports: Vec<SwayImport>,
    pub structs: Vec<SwayStruct>,
    pub enums: Vec<SwayEnum>,
    pub traits: Vec<SwayTrait>,
    pub constants: Vec<SwayConstant>,
}

#[derive(Debug, Clone)]
pub struct SwayFunction {
    pub name: String,
    pub visibility: FunctionVisibility,
    pub parameters: Vec<SwayParameter>,
    pub return_type: Option<SwayType>,
    pub body: Vec<SwayStatement>,
    pub span: Span,
    pub is_storage_function: bool,
    pub storage_reads: Vec<String>,
    pub storage_writes: Vec<String>,
    pub external_calls: Vec<SwayExternalCall>,
    pub require_statements: Vec<RequireStatement>,
    pub is_payable: bool,
    pub is_test: bool,
    pub is_script: bool,
    pub is_contract: bool,
    pub content: String, // Add content field for analysis
}

#[derive(Debug, Clone, PartialEq)]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
}

#[derive(Debug, Clone)]
pub struct SwayParameter {
    pub name: String,
    pub type_: SwayType,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayType {
    pub name: String,
    pub is_reference: bool,
    pub is_mutable: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayStatement {
    pub kind: StatementKind,
    pub span: Span,
    pub line_number: usize,
}

#[derive(Debug, Clone)]
pub enum StatementKind {
    Expression(Box<SwayExpression>),
    Let(LetStatement),
    Return(Option<Box<SwayExpression>>),
    Break,
    Continue,
    If(IfStatement),
    While(WhileStatement),
    For(ForStatement),
    Match(MatchStatement),
    Block(Vec<SwayStatement>),
    Storage(StorageStatement),
    Require(RequireStatement),
    Assert(AssertStatement),
}

#[derive(Debug, Clone)]
pub struct LetStatement {
    pub pattern: SwayPattern,
    pub type_: Option<SwayType>,
    pub value: Box<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct IfStatement {
    pub condition: Box<SwayExpression>,
    pub then_block: Vec<SwayStatement>,
    pub else_block: Option<Vec<SwayStatement>>,
}

#[derive(Debug, Clone)]
pub struct WhileStatement {
    pub condition: Box<SwayExpression>,
    pub body: Vec<SwayStatement>,
}

#[derive(Debug, Clone)]
pub struct ForStatement {
    pub pattern: SwayPattern,
    pub iterator: Box<SwayExpression>,
    pub body: Vec<SwayStatement>,
}

#[derive(Debug, Clone)]
pub struct MatchStatement {
    pub expression: Box<SwayExpression>,
    pub arms: Vec<MatchArm>,
}

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: SwayPattern,
    pub guard: Option<Box<SwayExpression>>,
    pub body: Vec<SwayStatement>,
}

#[derive(Debug, Clone)]
pub struct StorageStatement {
    pub field: String,
    pub operation: StorageOperation,
}

#[derive(Debug, Clone)]
pub enum StorageOperation {
    Read,
    Write,
    Both,
}

#[derive(Debug, Clone)]
pub struct RequireStatement {
    pub condition: Box<SwayExpression>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AssertStatement {
    pub condition: Box<SwayExpression>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwayExpression {
    pub kind: ExpressionKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum ExpressionKind {
    Literal(LiteralExpression),
    Variable(String),
    FunctionCall(FunctionCallExpression),
    MethodCall(MethodCallExpression),
    Binary(BinaryExpression),
    Unary(UnaryExpression),
    If(IfExpression),
    Match(MatchExpression),
    Block(Vec<SwayStatement>),
    Array(Vec<SwayExpression>),
    Tuple(Vec<SwayExpression>),
    Struct(StructExpression),
    Index(IndexExpression),
    Field(FieldExpression),
    Parenthesized(Box<SwayExpression>),
}

#[derive(Debug, Clone)]
pub struct LiteralExpression {
    pub value: String,
    pub type_: String,
}

#[derive(Debug, Clone)]
pub struct FunctionCallExpression {
    pub function: String,
    pub arguments: Vec<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct MethodCallExpression {
    pub receiver: Box<SwayExpression>,
    pub method: String,
    pub arguments: Vec<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct BinaryExpression {
    pub left: Box<SwayExpression>,
    pub operator: String,
    pub right: Box<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct UnaryExpression {
    pub operator: String,
    pub operand: Box<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct IfExpression {
    pub condition: Box<SwayExpression>,
    pub then_expr: Box<SwayExpression>,
    pub else_expr: Option<Box<SwayExpression>>,
}

#[derive(Debug, Clone)]
pub struct MatchExpression {
    pub expression: Box<SwayExpression>,
    pub arms: Vec<MatchArm>,
}

#[derive(Debug, Clone)]
pub struct StructExpression {
    pub struct_name: String,
    pub fields: Vec<StructField>,
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub value: SwayExpression,
}

#[derive(Debug, Clone)]
pub struct IndexExpression {
    pub array: Box<SwayExpression>,
    pub index: Box<SwayExpression>,
}

#[derive(Debug, Clone)]
pub struct FieldExpression {
    pub receiver: Box<SwayExpression>,
    pub field: String,
}

#[derive(Debug, Clone)]
pub struct SwayPattern {
    pub kind: PatternKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum PatternKind {
    Literal(String),
    Variable(String),
    Wildcard,
    Tuple(Vec<SwayPattern>),
    Struct(StructPattern),
    Or(Vec<SwayPattern>),
}

#[derive(Debug, Clone)]
pub struct StructPattern {
    pub struct_name: String,
    pub fields: Vec<StructPatternField>,
}

#[derive(Debug, Clone)]
pub struct StructPatternField {
    pub name: String,
    pub pattern: SwayPattern,
}

#[derive(Debug, Clone)]
pub struct SwayStorageField {
    pub name: String,
    pub type_: SwayType,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayImport {
    pub module: String,
    pub items: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayStruct {
    pub name: String,
    pub fields: Vec<SwayStructField>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayStructField {
    pub name: String,
    pub type_: SwayType,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayEnum {
    pub name: String,
    pub variants: Vec<SwayEnumVariant>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayEnumVariant {
    pub name: String,
    pub fields: Vec<SwayType>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayTrait {
    pub name: String,
    pub functions: Vec<SwayTraitFunction>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayTraitFunction {
    pub name: String,
    pub parameters: Vec<SwayParameter>,
    pub return_type: Option<SwayType>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayConstant {
    pub name: String,
    pub type_: SwayType,
    pub value: SwayExpression,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SwayExternalCall {
    pub function: String,
    pub arguments: Vec<SwayExpression>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    
    pub fn start(&self) -> usize {
        self.start
    }
    
    pub fn end(&self) -> usize {
        self.end
    }
}

impl std::fmt::Display for SwayExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ExpressionKind::Literal(lit) => write!(f, "{}", lit.value),
            ExpressionKind::Variable(var) => write!(f, "{}", var),
            ExpressionKind::FunctionCall(call) => write!(f, "{}(...)", call.function),
            ExpressionKind::MethodCall(call) => write!(f, "{}.{}(...)", call.receiver, call.method),
            ExpressionKind::Binary(bin) => write!(f, "{} {} {}", bin.left, bin.operator, bin.right),
            ExpressionKind::Unary(un) => write!(f, "{}{}", un.operator, un.operand),
            ExpressionKind::If(if_expr) => write!(f, "if {} then ... else ...", if_expr.condition),
            ExpressionKind::Match(match_expr) => write!(f, "match {} {{ ... }}", match_expr.expression),
            ExpressionKind::Block(_) => write!(f, "{{ ... }}"),
            ExpressionKind::Array(_) => write!(f, "[...]"),
            ExpressionKind::Tuple(_) => write!(f, "(...)"),
            ExpressionKind::Struct(_) => write!(f, "Struct {{ ... }}"),
            ExpressionKind::Index(_) => write!(f, "array[index]"),
            ExpressionKind::Field(_) => write!(f, "object.field"),
            ExpressionKind::Parenthesized(expr) => write!(f, "({})", expr),
        }
    }
}

pub struct SwayParser;

impl SwayParser {
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<SwayFile, SwayscanError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        
        // Create a simple AST without using the complex Sway parser
        let mut ast = Self::create_simple_ast(&content)?;
        
        Ok(SwayFile {
            path: path.to_string_lossy().to_string(),
            content,
            ast: Some(ast),
        })
    }

    fn create_simple_ast(content: &str) -> Result<SwayAst, SwayscanError> {
        let mut ast = SwayAst {
            functions: Vec::new(),
            structs: Vec::new(),
            enums: Vec::new(),
            imports: Vec::new(),
            storage_fields: Vec::new(),
            traits: Vec::new(),
            constants: Vec::new(),
        };
        
        // Extract functions from content
        ast.extract_functions_from_content(content);
        
        Ok(ast)
    }
}

impl SwayAst {
    fn extract_functions_from_content(&mut self, content: &str) {
        let lines: Vec<&str> = content.lines().collect();
        let mut current_function: Option<String> = None;
        let mut function_lines: Vec<&str> = Vec::new();
        let mut brace_depth = 0;
        let mut in_function = false;
        let mut function_start_line = 0;
        let mut function_end_line = 0;
        
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // Detect function start - look for various patterns
            if Self::is_function_start(trimmed) {
                // Process previous function if exists
                if let Some(func_name) = &current_function {
                    self.process_function_content(func_name, &function_lines, function_start_line, function_end_line);
                }
                // Extract function name
                if let Some(func_name) = Self::extract_function_name(trimmed) {
                    current_function = Some(func_name.clone());
                    function_lines.clear();
                    brace_depth = 0;
                    in_function = true;
                    function_lines.push(line);
                    function_start_line = line_num + 1; // 1-based line number
                    function_end_line = function_start_line;
                    // Count opening braces in the function declaration line
                    for ch in line.chars() {
                        if ch == '{' {
                            brace_depth += 1;
                        }
                    }
                }
            } else if in_function {
                function_lines.push(line);
                // Track brace depth
                for ch in line.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => brace_depth -= 1,
                        _ => {}
                    }
                }
                function_end_line = line_num + 1;
                // Function ended when we return to brace_depth 0
                if brace_depth == 0 && !function_lines.is_empty() {
                    if let Some(func_name) = &current_function {
                        self.process_function_content(func_name, &function_lines, function_start_line, function_end_line);
                    }
                    current_function = None;
                    function_lines.clear();
                    in_function = false;
                }
            }
        }
        // Process last function if exists
        if let Some(func_name) = &current_function {
            self.process_function_content(func_name, &function_lines, function_start_line, function_end_line);
        }
    }

    fn is_function_start(line: &str) -> bool {
        let trimmed = line.trim();
        
        // Check for various function declaration patterns
        trimmed.starts_with("fn ") ||
        trimmed.starts_with("pub fn ") ||
        trimmed.starts_with("storage fn ") ||
        trimmed.starts_with("pub storage fn ") ||
        trimmed.contains(" fn ") && trimmed.contains("(")
    }

    fn extract_function_name(line: &str) -> Option<String> {
        let trimmed = line.trim();
        
        // Match various function declaration patterns
        let patterns = [
            r"fn\s+(\w+)",
            r"pub\s+fn\s+(\w+)",
            r"storage\s+fn\s+(\w+)",
            r"pub\s+storage\s+fn\s+(\w+)",
        ];
        
        for pattern in &patterns {
            if let Some(captures) = regex::Regex::new(pattern).ok().and_then(|re| re.captures(trimmed)) {
                if let Some(name) = captures.get(1) {
                    return Some(name.as_str().to_string());
                }
            }
        }
        
        // Fallback: try to extract function name manually
        if let Some(fn_pos) = trimmed.find(" fn ") {
            let after_fn = &trimmed[fn_pos + 4..];
            if let Some(paren_pos) = after_fn.find('(') {
                return Some(after_fn[..paren_pos].trim().to_string());
            }
        }
        
        None
    }

    fn process_function_content(&mut self, func_name: &str, function_lines: &[&str], start_line: usize, end_line: usize) {
        let content = function_lines.join("\n");
        // Create the function object with better content extraction
        let function = SwayFunction {
            name: func_name.to_string(),
            visibility: if content.contains("pub fn") || content.contains("pub ") { 
                FunctionVisibility::Public 
            } else { 
                FunctionVisibility::Private 
            },
            parameters: Vec::new(),
            return_type: None,
            body: Vec::new(),
            span: Span::new(start_line, end_line),
            is_storage_function: content.contains("storage"),
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            external_calls: Vec::new(),
            require_statements: Vec::new(),
            is_payable: content.contains("payable"),
            is_contract: true,
            is_script: false,
            is_test: false,
            content: content.clone(), // Store the full content
        };
        // Add the function to the vector
        self.functions.push(function);
        // Now analyze the content for operations
        self.analyze_function_operations(func_name, &content);
    }

    fn analyze_function_operations(&mut self, func_name: &str, content: &str) {
        // Find the function in our vector
        if let Some(function) = self.functions.iter_mut().find(|f| f.name == func_name) {
            // Detect storage operations
            if content.contains("storage.") {
                function.storage_writes.push("storage_operation".to_string());
            }
            
            // Detect external calls
            let external_call_patterns = [
                "transfer(", "mint_to(", "burn(", "call(", "delegate_call(",
                "require(", "assert(", "revert("
            ];
            
            for pattern in &external_call_patterns {
                if content.contains(pattern) {
                    function.external_calls.push(SwayExternalCall {
                        function: pattern.trim_end_matches('(').to_string(),
                        arguments: Vec::new(),
                        span: Span::new(0, 0),
                    });
                }
            }
            
            // Detect require statements
            if content.contains("require(") {
                function.require_statements.push(RequireStatement {
                    condition: Box::new(SwayExpression {
                        kind: ExpressionKind::Variable("condition".to_string()),
                        span: Span::new(0, 0),
                    }),
                    message: Some("Access control check".to_string()),
                });
            }
        }
    }

    pub fn get_function_by_name(&self, name: &str) -> Option<&SwayFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    pub fn get_storage_field_by_name(&self, name: &str) -> Option<&SwayStorageField> {
        self.storage_fields.iter().find(|f| f.name == name)
    }

    pub fn get_all_functions(&self) -> &[SwayFunction] {
        &self.functions
    }

    pub fn get_all_storage_fields(&self) -> &[SwayStorageField] {
        &self.storage_fields
    }
}