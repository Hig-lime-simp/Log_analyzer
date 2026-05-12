use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize}; // Парс из\в json

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry { //конструктор обьекта(структуры)
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel { // спсиок всех типов логов
    Info,
    Warning,
    Error,
}

impl LogEntry { // Создание лога 
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
        if lower.contains("error") {
            LogLevel::Error
        } else if lower.contains("warning") {
            LogLevel::Warning
        } else {
            LogLevel::Info
        }
    }
}