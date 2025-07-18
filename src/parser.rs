use crate::error::SwayscanError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SwayFile {
    pub path: String,
    pub content: String,
}

pub struct SwayParser;

impl SwayParser {
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<SwayFile, SwayscanError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        
        Ok(SwayFile {
            path: path.to_string_lossy().to_string(),
            content,
        })
    }
}