use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum SwayscanError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Parse error at line {line}, column {column}: {message}")]
    Parse {
        line: usize,
        column: usize,
        message: String,
    },
    
    #[error("Invalid file extension: {0}. Expected .sw files")]
    InvalidFileExtension(String),
    
    #[error("No Sway files found in the specified path: {0}")]
    NoSwayFiles(String),
    
    #[error("Unknown detector: {0}")]
    UnknownDetector(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Analysis error: {0}")]
    Analysis(String),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
}

impl SwayscanError {
    pub fn config_error(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }
}