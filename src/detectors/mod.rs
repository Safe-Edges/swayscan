use crate::error::SwayscanError;
use crate::parser::SwayFile;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// Keep only robust detector implementations
pub mod unprotected_storage;
pub mod reentrancy;
pub mod access_control;
pub mod data_validation;
pub mod cryptographic;
pub mod business_logic;
pub mod price_oracle_manipulation;
pub mod flash_loan_attacks;
pub mod unchecked_external_calls;
pub mod utxo_vulnerabilities;
pub mod logic_errors;
pub mod input_validation;
pub mod division_before_multiplication;
pub mod arbitrary_asset_transfer;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum Category {
    Security,
    Performance,
    Maintainability,
    Reliability,
    Compliance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub detector_name: String,
    pub severity: Severity,
    pub category: Category,
    pub confidence: f64, // 0.0 to 1.0
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub code_snippet: String,
    pub recommendation: String,
    pub impact: String,
    pub effort: EstimatedEffort,
    pub references: Vec<Reference>,
    pub cwe_ids: Vec<u32>,
    pub owasp_category: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub fingerprint: String,
    pub context: AnalysisContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EstimatedEffort {
    Trivial,    // < 1 hour
    Easy,       // 1-4 hours  
    Medium,     // 1-2 days
    Hard,       // 3-5 days
    Expert,     // > 1 week
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
    pub reference_type: ReferenceType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferenceType {
    Documentation,
    BestPractice,
    Vulnerability,
    Tool,
    Academic,
    Security,
    Standard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub function_name: Option<String>,
    pub contract_type: Option<String>,
    pub dependencies: Vec<String>,
    pub complexity_score: Option<u32>,
    pub call_depth: Option<u32>,
    pub variables_in_scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub code_snippet: String,
    pub function_name: Option<String>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        detector_name: impl Into<String>,
        severity: Severity,
        category: Category,
        confidence: f64,
        title: impl Into<String>,
        description: impl Into<String>,
        file_path: impl Into<String>,
        line: usize,
        column: usize,
        code_snippet: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        let file_path = file_path.into();
        let code_snippet = code_snippet.into();
        
        Self {
            id: Uuid::new_v4(),
            detector_name: detector_name.into(),
            category: category.clone(),
            confidence,
            title: title.into(),
            description: description.into(),
            file_path: file_path.clone(),
            line,
            column,
            end_line: None,
            end_column: None,
            code_snippet: code_snippet.clone(),
            recommendation: recommendation.into(),
            impact: Self::generate_impact_description(&severity),
            effort: Self::estimate_effort(&severity),
            severity: severity.clone(),
            references: Vec::new(),
            cwe_ids: Vec::new(),
            owasp_category: None,
            tags: Vec::new(),
            created_at: Utc::now(),
            fingerprint: Self::generate_fingerprint(&file_path, line, column, &code_snippet),
            context: AnalysisContext {
                function_name: None,
                contract_type: None,
                dependencies: Vec::new(),
                complexity_score: None,
                call_depth: None,
                variables_in_scope: Vec::new(),
            },
        }
    }

    pub fn with_context(mut self, context: AnalysisContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_cwe(mut self, cwe_ids: Vec<u32>) -> Self {
        self.cwe_ids = cwe_ids;
        self
    }

    pub fn with_references(mut self, references: Vec<Reference>) -> Self {
        self.references = references;
        self
    }

    pub fn with_range(mut self, end_line: usize, end_column: usize) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }

    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = impact.into();
        self
    }

    pub fn with_effort(mut self, effort: EstimatedEffort) -> Self {
        self.effort = effort;
        self
    }

    fn generate_impact_description(severity: &Severity) -> String {
        match severity {
            Severity::Critical => "Critical security vulnerability that could lead to loss of funds or complete contract compromise".to_string(),
            Severity::High => "High-risk issue that could lead to security vulnerabilities or significant functional problems".to_string(),
            Severity::Medium => "Medium-risk issue that may impact security, performance, or maintainability".to_string(),
            Severity::Low => "Low-risk issue that affects code quality or minor best practices".to_string(),
        }
    }

    fn estimate_effort(severity: &Severity) -> EstimatedEffort {
        match severity {
            Severity::Critical => EstimatedEffort::Expert,
            Severity::High => EstimatedEffort::Hard,
            Severity::Medium => EstimatedEffort::Medium,
            Severity::Low => EstimatedEffort::Easy,
        }
    }

    fn generate_fingerprint(file_path: &str, line: usize, column: usize, code_snippet: &str) -> String {
        use sha2::{Digest, Sha256};
        let input = format!("{}:{}:{}:{}", file_path, line, column, code_snippet);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 10,
            Severity::High => 7,
            Severity::Medium => 4,
            Severity::Low => 1,
        }
    }
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> Category;
    fn default_severity(&self) -> Severity;
    
    fn analyze(&self, file: &SwayFile, context: &AnalysisContext) -> Result<Vec<Finding>, SwayscanError>;
    
    fn supports_file_type(&self, _file_path: &str) -> bool {
        true // By default, all detectors support all Sway files
    }
    
    fn requires_dependencies(&self) -> bool {
        false
    }
    
    fn is_experimental(&self) -> bool {
        false
    }
}

pub struct DetectorRegistry {
    detectors: HashMap<String, Box<dyn Detector>>,
    detector_metadata: HashMap<String, DetectorMetadata>,
}

#[derive(Debug, Clone)]
pub struct DetectorMetadata {
    pub enabled: bool,
    pub confidence_threshold: f64,
    pub custom_config: HashMap<String, String>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            detectors: HashMap::new(),
            detector_metadata: HashMap::new(),
        };
        
        // Register only robust detectors with proper implementations
        registry.register(Box::new(unprotected_storage::UnprotectedStorageDetector::new()));
        registry.register(Box::new(reentrancy::ReentrancyDetector::new()));
        registry.register(Box::new(access_control::AccessControlDetector::new()));
        registry.register(Box::new(data_validation::DataValidationDetector::new()));
        registry.register(Box::new(cryptographic::CryptographicDetector::new()));
        registry.register(Box::new(business_logic::BusinessLogicDetector::new()));
        registry.register(Box::new(price_oracle_manipulation::PriceOracleDetector::new()));
        registry.register(Box::new(flash_loan_attacks::FlashLoanDetector::new()));
        registry.register(Box::new(unchecked_external_calls::UncheckedExternalCallDetector::new()));
        registry.register(Box::new(utxo_vulnerabilities::UtxoVulnerabilityDetector::new()));
        registry.register(Box::new(logic_errors::LogicErrorDetector::new()));
        registry.register(Box::new(input_validation::InputValidationDetector::new()));
        registry.register(Box::new(division_before_multiplication::DivisionBeforeMultiplicationDetector::new()));
        registry.register(Box::new(arbitrary_asset_transfer::ArbitraryAssetTransferDetector::new()));
        
        registry
    }
    
    fn register(&mut self, detector: Box<dyn Detector>) {
        let name = detector.name().to_string();
        self.detector_metadata.insert(name.clone(), DetectorMetadata {
            enabled: true,
            confidence_threshold: 0.7,
            custom_config: HashMap::new(),
        });
        self.detectors.insert(name, detector);
    }
    
    pub fn get_detector(&self, name: &str) -> Option<&Box<dyn Detector>> {
        self.detectors.get(name)
    }
    
    pub fn get_all_detectors(&self) -> Vec<&Box<dyn Detector>> {
        self.detectors.values().collect()
    }
    
    pub fn get_selected_detectors(&self, include_list: &[String], exclude_list: &[String]) -> Vec<&Box<dyn Detector>> {
        self.detectors
            .iter()
            .filter(|(name, _)| {
                let included = include_list.is_empty() || include_list.contains(name);
                let not_excluded = !exclude_list.contains(name);
                let enabled = self.detector_metadata.get(*name)
                    .map(|meta| meta.enabled)
                    .unwrap_or(true);
                included && not_excluded && enabled
            })
            .map(|(_, detector)| detector)
            .collect()
    }
    
    pub fn list_available_detectors(&self) -> Vec<&str> {
        self.detectors.keys().map(|s| s.as_str()).collect()
    }
    
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }
    
    pub fn get_detector_info(&self, name: &str) -> Option<DetectorInfo> {
        self.detectors.get(name).map(|detector| DetectorInfo {
            name: detector.name(),
            description: detector.description(),
            category: detector.category(),
            default_severity: detector.default_severity(),
            is_experimental: detector.is_experimental(),
            requires_dependencies: detector.requires_dependencies(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DetectorInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub category: Category,
    pub default_severity: Severity,
    pub is_experimental: bool,
    pub requires_dependencies: bool,
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Utility functions for detectors
pub fn extract_code_snippet(content: &str, line: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(context_lines + 1);
    let end = std::cmp::min(line + context_lines, lines.len());
    
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line_content)| {
            let line_num = start + i + 1;
            if line_num == line {
                format!(">>> {}: {}", line_num, line_content)
            } else {
                format!("    {}: {}", line_num, line_content)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn is_numeric_literal(expr: &str) -> bool {
    expr.chars().all(|c| c.is_ascii_digit() || c == '_' || c == '.')
}

pub fn is_large_number(value: u64) -> bool {
    value > 10000
}

pub fn has_access_control_patterns(function_name: &str, content: &str) -> bool {
    let access_patterns = [
        "require(",
        "assert(",
        "only_owner",
        "require_auth",
        "check_",
        "validate_",
        "auth_",
        "admin_",
        "owner",
        "msg_sender()",
    ];
    
    access_patterns.iter().any(|pattern| {
        function_name.contains(pattern) || content.contains(pattern)
    })
}

pub fn calculate_cyclomatic_complexity(content: &str) -> u32 {
    let complexity_keywords = ["if", "while", "for", "match", "&&", "||"];
    let mut complexity = 1; // Base complexity
    
    for keyword in complexity_keywords {
        complexity += content.matches(keyword).count() as u32;
    }
    
    complexity
}

pub fn detect_external_calls(content: &str) -> Vec<String> {
    let mut external_calls = Vec::new();
    
    // Common patterns for external calls in Sway
    let patterns = [
        r"\.call\(",
        r"\.transfer\(",
        r"\.send\(",
        r"abi\(",
    ];
    
    for pattern in patterns {
        if let Ok(regex) = regex::Regex::new(pattern) {
            for match_result in regex.find_iter(content) {
                external_calls.push(match_result.as_str().to_string());
            }
        }
    }
    
    external_calls
}

#[derive(Debug, Clone)]
pub struct AnalysisStatistics {
    pub total_lines_analyzed: usize,
    pub total_functions_analyzed: usize,
    pub total_files_analyzed: usize,
    pub analysis_duration_ms: u128,
    pub detectors_run: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub findings_by_category: HashMap<Category, usize>,
    pub false_positive_rate: f64,
}

impl AnalysisStatistics {
    pub fn new() -> Self {
        Self {
            total_lines_analyzed: 0,
            total_functions_analyzed: 0,
            total_files_analyzed: 0,
            analysis_duration_ms: 0,
            detectors_run: 0,
            findings_by_severity: HashMap::new(),
            findings_by_category: HashMap::new(),
            false_positive_rate: 0.0,
        }
    }
    
    pub fn add_findings(&mut self, findings: &[Finding]) {
        for finding in findings {
            *self.findings_by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
            *self.findings_by_category.entry(finding.category.clone()).or_insert(0) += 1;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedFinding {
    pub id: Uuid,
    pub detector_name: String,
    pub severity: Severity,
    pub category: Category,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub locations: Vec<Location>,
    pub recommendation: String,
    pub impact: String,
    pub effort: EstimatedEffort,
    pub references: Vec<Reference>,
    pub cwe_ids: Vec<u32>,
    pub owasp_category: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub fingerprint: String,
    pub context: AnalysisContext,
    pub occurrence_count: usize,
}

impl GroupedFinding {
    pub fn from_finding(finding: Finding) -> Self {
        let location = Location {
            file_path: finding.file_path.clone(),
            line: finding.line,
            column: finding.column,
            end_line: finding.end_line,
            end_column: finding.end_column,
            code_snippet: finding.code_snippet.clone(),
            function_name: finding.context.function_name.clone(),
        };

        Self {
            id: finding.id,
            detector_name: finding.detector_name,
            severity: finding.severity,
            category: finding.category,
            confidence: finding.confidence,
            title: finding.title,
            description: finding.description,
            locations: vec![location],
            recommendation: finding.recommendation,
            impact: finding.impact,
            effort: finding.effort,
            references: finding.references,
            cwe_ids: finding.cwe_ids,
            owasp_category: finding.owasp_category,
            tags: finding.tags,
            created_at: finding.created_at,
            fingerprint: finding.fingerprint,
            context: finding.context,
            occurrence_count: 1,
        }
    }

    pub fn add_occurrence(&mut self, finding: Finding) {
        let location = Location {
            file_path: finding.file_path,
            line: finding.line,
            column: finding.column,
            end_line: finding.end_line,
            end_column: finding.end_column,
            code_snippet: finding.code_snippet,
            function_name: finding.context.function_name,
        };

        self.locations.push(location);
        self.occurrence_count += 1;
        
        // Update confidence to average if new finding has different confidence
        if (self.confidence - finding.confidence).abs() > 0.01 {
            self.confidence = (self.confidence * (self.occurrence_count - 1) as f64 + finding.confidence) / self.occurrence_count as f64;
        }
    }

    /// Generate a key for grouping similar findings
    pub fn grouping_key(&self) -> String {
        format!("{}::{}", self.detector_name, self.title)
    }
}

pub fn group_findings(findings: Vec<Finding>) -> Vec<GroupedFinding> {
    use std::collections::HashMap;
    
    let mut groups: HashMap<String, GroupedFinding> = HashMap::new();
    
    for finding in findings {
        let key = format!("{}::{}", finding.detector_name, finding.title);
        
        if let Some(grouped) = groups.get_mut(&key) {
            grouped.add_occurrence(finding);
        } else {
            groups.insert(key, GroupedFinding::from_finding(finding));
        }
    }
    
    let mut grouped_findings: Vec<GroupedFinding> = groups.into_values().collect();
    
    // Sort by severity (highest first), then by occurrence count (most first)
    grouped_findings.sort_by(|a, b| {
        match b.severity.cmp(&a.severity) {
            std::cmp::Ordering::Equal => b.occurrence_count.cmp(&a.occurrence_count),
            other => other,
        }
    });
    
    grouped_findings
}