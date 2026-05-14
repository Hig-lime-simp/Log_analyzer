//! Data models for log analyzer

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log level enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
    Trace,
    Unknown,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

impl From<&str> for LogLevel {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "INFO" => LogLevel::Info,
            "WARN" | "WARNING" => LogLevel::Warn,
            "ERROR" | "ERR" => LogLevel::Error,
            "DEBUG" => LogLevel::Debug,
            "TRACE" => LogLevel::Trace,
            _ => LogLevel::Unknown,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Parsed log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp of the log entry
    pub timestamp: DateTime<Utc>,
    /// Log level
    pub level: LogLevel,
    /// Log message text
    pub message: String,
    /// Source file or service name
    pub source: Option<String>,
    /// Additional key-value parameters
    pub params: HashMap<String, String>,
    /// Raw original line
    pub raw_line: String,
    /// File path where the log was found
    pub file_path: String,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        level: LogLevel,
        message: String,
        raw_line: String,
        file_path: String,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message,
            source: None,
            params: HashMap::new(),
            raw_line,
            file_path,
        }
    }

    /// Set the source of the log entry
    pub fn with_source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    /// Add a parameter to the log entry
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.params.insert(key, value);
        self
    }

    /// Check if the log entry contains a keyword
    pub fn contains_keyword(&self, keyword: &str) -> bool {
        self.message.contains(keyword)
            || self.raw_line.contains(keyword)
            || self.source.as_ref().map_or(false, |s| s.contains(keyword))
    }
}

/// Aggregated statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Statistics {
    /// Total number of processed log entries
    pub total_entries: u64,
    /// Count by log level
    pub by_level: HashMap<LogLevel, u64>,
    /// Count by source
    pub by_source: HashMap<String, u64>,
    /// Count by file path
    pub by_file: HashMap<String, u64>,
    /// Time of last update
    pub last_updated: DateTime<Utc>,
}

impl Statistics {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Update statistics with a new log entry
    pub fn update(&mut self, entry: &LogEntry) {
        self.total_entries += 1;
        
        *self.by_level.entry(entry.level.clone()).or_insert(0) += 1;
        
        if let Some(ref source) = entry.source {
            *self.by_source.entry(source.clone()).or_insert(0) += 1;
        }
        
        *self.by_file.entry(entry.file_path.clone()).or_insert(0) += 1;
        
        self.last_updated = Utc::now();
    }

    /// Get count for a specific log level
    pub fn get_level_count(&self, level: &LogLevel) -> u64 {
        *self.by_level.get(level).unwrap_or(&0)
    }

    /// Get error rate (errors / total)
    pub fn error_rate(&self) -> f64 {
        if self.total_entries == 0 {
            return 0.0;
        }
        let errors = self.get_level_count(&LogLevel::Error);
        errors as f64 / self.total_entries as f64
    }
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Description of the anomaly
    pub description: String,
    /// Timestamp when detected
    pub detected_at: DateTime<Utc>,
    /// Severity level
    pub severity: Severity,
    /// Related log entries (optional)
    pub related_entries: Vec<LogEntry>,
}

/// Types of anomalies that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Too many errors in a time window
    ErrorSpike,
    /// Repeated identical events
    RepeatedEvent,
    /// Sudden increase in log volume
    VolumeSpike,
    /// Custom rule violation
    RuleViolation,
}

/// Severity levels for anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Filter criteria for log entries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    /// Filter by log levels (if empty, all levels are included)
    pub levels: Vec<LogLevel>,
    /// Filter by keyword (substring match)
    pub keyword: Option<String>,
    /// Filter by source
    pub source: Option<String>,
    /// Filter by file path pattern
    pub file_pattern: Option<String>,
}

impl LogFilter {
    /// Check if a log entry matches the filter
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Check level filter
        if !self.levels.is_empty() && !self.levels.contains(&entry.level) {
            return false;
        }

        // Check keyword filter
        if let Some(ref keyword) = self.keyword {
            if !entry.contains_keyword(keyword) {
                return false;
            }
        }

        // Check source filter
        if let Some(ref source) = self.source {
            if entry.source.as_ref().map_or(true, |s| s != source) {
                return false;
            }
        }

        // Check file pattern filter
        if let Some(ref pattern) = self.file_pattern {
            if !entry.file_path.contains(pattern) {
                return false;
            }
        }

        true
    }
}
