use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwayscanConfig {
    pub detectors: DetectorConfig,
    pub output: OutputConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub enabled: Vec<String>,
    pub disabled: Vec<String>,
    pub confidence_threshold: f64,
    pub custom_rules: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub file: Option<String>,
    pub include_context: bool,
    pub include_references: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub parallel_threads: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub max_file_size_mb: Option<u64>,
}

impl Default for SwayscanConfig {
    fn default() -> Self {
        Self {
            detectors: DetectorConfig {
                enabled: Vec::new(),
                disabled: Vec::new(),
                confidence_threshold: 0.7,
                custom_rules: HashMap::new(),
            },
            output: OutputConfig {
                format: "text".to_string(),
                file: None,
                include_context: true,
                include_references: true,
            },
            analysis: AnalysisConfig {
                parallel_threads: None,
                timeout_seconds: Some(300),
                max_file_size_mb: Some(10),
            },
        }
    }
}

impl SwayscanConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: SwayscanConfig = toml::from_str(&content)?;
        Ok(config)
    }
} 