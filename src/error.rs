//! Error handling module for the log analyzer

use thiserror::Error;

/// Main error type for the log analyzer
#[derive(Error, Debug)]
pub enum LogAnalyzerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid log format: {0}")]
    InvalidLogFormat(String),

    #[error("Anomaly detection error: {0}")]
    AnomalyDetection(String),
}

/// Result type alias for log analyzer operations
pub type Result<T> = std::result::Result<T, LogAnalyzerError>;

impl From<serde_json::Error> for LogAnalyzerError {
    fn from(err: serde_json::Error) -> Self {
        LogAnalyzerError::Config(format!("JSON parse error: {}", err))
    }
}

impl From<toml::de::Error> for LogAnalyzerError {
    fn from(err: toml::de::Error) -> Self {
        LogAnalyzerError::Config(format!("TOML parse error: {}", err))
    }
}

impl From<regex::Error> for LogAnalyzerError {
    fn from(err: regex::Error) -> Self {
        LogAnalyzerError::Parse(format!("Regex error: {}", err))
    }
}
