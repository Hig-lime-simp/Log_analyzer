use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl LogEntry {
    pub fn new(id: u64, content: String) -> Self {
        let level = Self::detect_level(&content);
        Self {
            id,
            timestamp: Utc::now(),
            level,
            content,
        }
    }
    
    fn detect_level(content: &str) -> LogLevel {
        let lower = content.to_lowercase();
        if lower.contains("error") || lower.contains("fail") || lower.contains("critical") {
            LogLevel::Error
        } else if lower.contains("warning") || lower.contains("warn") {
            LogLevel::Warning
        } else {
            LogLevel::Info
        }
    }
}