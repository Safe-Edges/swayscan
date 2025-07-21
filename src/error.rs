use thiserror::Error;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum SwayscanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Analysis error: {0}")]
    Analysis(String),
    
    #[error("Report generation error: {0}")]
    Report(String),
    
    #[error("Scanner error: {0}")]
    Scanner(String),
    
    #[error("Detector error: {0}")]
    Detector(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("File error: {0}")]
    File(String),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("No Sway files found: {0}")]
    NoSwayFiles(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl SwayscanError {
    pub fn config_error(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }
    
    pub fn analysis_error(message: impl Into<String>) -> Self {
        Self::Analysis(message.into())
    }
    
    pub fn report_error(message: impl Into<String>) -> Self {
        Self::Report(message.into())
    }
    
    pub fn scanner_error(message: impl Into<String>) -> Self {
        Self::Scanner(message.into())
    }
    
    pub fn detector_error(message: impl Into<String>) -> Self {
        Self::Detector(message.into())
    }
    
    pub fn validation_error(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }
    
    pub fn file_error(message: impl Into<String>) -> Self {
        Self::File(message.into())
    }
    
    pub fn serialization_error(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }
    
    pub fn deserialization_error(message: impl Into<String>) -> Self {
        Self::Deserialization(message.into())
    }
    
    pub fn unknown_error(message: impl Into<String>) -> Self {
        Self::Unknown(message.into())
    }
}