//! Data models for log analyzer

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log levels representing severity of log entries
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    /// Trace level - very detailed debugging information
    Trace,
    /// Debug level - debugging information
    Debug,
    /// Info level - general informational messages
    Info,
    /// Warn level - warning messages
    Warn,
    /// Error level - error messages
    Error,
    /// Unknown level - for unparsable log levels
    Unknown,
}

impl LogLevel {
    /// Convert string to LogLevel
    pub fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" | "err" => LogLevel::Error,
            _ => LogLevel::Unknown,
        }
    }

    /// Get numeric priority (higher = more severe)
    pub fn priority(&self) -> u8 {
        match self {
            LogLevel::Trace => 0,
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warn => 3,
            LogLevel::Error => 4,
            LogLevel::Unknown => 5,
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

/// Represents a single log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp when the log was created
    pub timestamp: DateTime<Utc>,
    /// Log level
    pub level: LogLevel,
    /// Log message content
    pub message: String,
    /// Optional source/service name
    pub source: Option<String>,
    /// Optional user identifier
    pub user: Option<String>,
    /// Additional key-value parameters
    pub params: HashMap<String, String>,
    /// Raw original log line
    pub raw_line: String,
    /// Path to the file this log came from
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
            user: None,
            params: HashMap::new(),
            raw_line,
            file_path,
        }
    }

    /// Create a log entry with source
    pub fn with_source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    /// Create a log entry with user
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    /// Add a parameter to the log entry
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.params.insert(key, value);
        self
    }

    /// Check if the log entry contains a keyword (case-insensitive)
    pub fn contains_keyword(&self, keyword: &str) -> bool {
        self.message.to_lowercase().contains(&keyword.to_lowercase())
            || self.raw_line.to_lowercase().contains(&keyword.to_lowercase())
    }

    /// Parse additional parameters from message
    /// Expected format: key=value or key="value with spaces"
    pub fn parse_params(&mut self) {
        let re = regex::Regex::new(r#"(\w+)=(?:"([^"]*)"|(\S+))"#).unwrap();
        for cap in re.captures_iter(&self.message) {
            let key = cap[1].to_string();
            let value = cap.get(2).map_or_else(|| cap[3].to_string(), |m| m.as_str().to_string());
            self.params.insert(key, value);
        }
    }
}

/// Statistics for log analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Statistics {
    /// Total number of log entries processed
    pub total_entries: u64,
    /// Count of entries by log level
    pub level_counts: HashMap<LogLevel, u64>,
    /// Count of entries by source (if available)
    pub source_counts: HashMap<String, u64>,
    /// Count of entries by user (if available)
    pub user_counts: HashMap<String, u64>,
    /// First entry timestamp
    pub first_entry: Option<DateTime<Utc>>,
    /// Last entry timestamp
    pub last_entry: Option<DateTime<Utc>>,
    /// Count of repeated messages (for anomaly detection)
    pub repeated_messages: HashMap<String, u64>,
}

impl Statistics {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Update statistics with a new log entry
    pub fn update(&mut self, entry: &LogEntry) {
        self.total_entries += 1;

        // Update level counts
        *self.level_counts.entry(entry.level.clone()).or_insert(0) += 1;

        // Update source counts
        if let Some(ref source) = entry.source {
            *self.source_counts.entry(source.clone()).or_insert(0) += 1;
        }

        // Update user counts
        if let Some(ref user) = entry.user {
            *self.user_counts.entry(user.clone()).or_insert(0) += 1;
        }

        // Update timestamps
        if self.first_entry.is_none() {
            self.first_entry = Some(entry.timestamp);
        }
        self.last_entry = Some(entry.timestamp);

        // Track repeated messages
        *self.repeated_messages.entry(entry.message.clone()).or_insert(0) += 1;
    }

    /// Get count for a specific log level
    pub fn get_level_count(&self, level: &LogLevel) -> u64 {
        *self.level_counts.get(level).unwrap_or(&0)
    }

    /// Calculate error rate (errors / total)
    pub fn error_rate(&self) -> f64 {
        if self.total_entries == 0 {
            return 0.0;
        }
        let errors = self.get_level_count(&LogLevel::Error);
        errors as f64 / self.total_entries as f64
    }

    /// Calculate warn rate (warnings / total)
    pub fn warn_rate(&self) -> f64 {
        if self.total_entries == 0 {
            return 0.0;
        }
        let warns = self.get_level_count(&LogLevel::Warn);
        warns as f64 / self.total_entries as f64
    }

    /// Get duration of log collection
    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.first_entry, self.last_entry) {
            (Some(first), Some(last)) => Some(last - first),
            _ => None,
        }
    }

    /// Get most frequent sources
    pub fn top_sources(&self, n: usize) -> Vec<(String, u64)> {
        let mut sources: Vec<_> = self.source_counts.iter().collect();
        sources.sort_by(|a, b| b.1.cmp(a.1));
        sources.into_iter().take(n).map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Get most repeated messages
    pub fn top_repeated(&self, n: usize) -> Vec<(String, u64)> {
        let mut messages: Vec<_> = self.repeated_messages.iter().collect();
        messages.sort_by(|a, b| b.1.cmp(a.1));
        messages.into_iter().take(n).map(|(k, v)| (k.clone(), *v)).collect()
    }
}

/// Severity levels for anomalies and warnings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity - informational
    Low,
    /// Medium severity - worth noting
    Medium,
    /// High severity - requires attention
    High,
    /// Critical severity - immediate action required
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Low
    }
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

/// Types of anomalies that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Sudden spike in error count
    ErrorSpike,
    /// Repeated identical events
    RepeatedEvent,
    /// Sudden increase in log volume
    VolumeSpike,
    /// Rule-based violation
    RuleViolation,
}

/// Represents a detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Type of anomaly detected
    pub anomaly_type: AnomalyType,
    /// Human-readable description
    pub description: String,
    /// When the anomaly was detected
    pub detected_at: DateTime<Utc>,
    /// Severity of the anomaly
    pub severity: Severity,
    /// Related log entries (if any)
    pub related_entries: Vec<LogEntry>,
}

impl Anomaly {
    /// Create a new anomaly
    pub fn new(
        anomaly_type: AnomalyType,
        description: String,
        severity: Severity,
    ) -> Self {
        Self {
            anomaly_type,
            description,
            detected_at: Utc::now(),
            severity,
            related_entries: Vec::new(),
        }
    }

    /// Add related log entries
    pub fn with_entries(mut self, entries: Vec<LogEntry>) -> Self {
        self.related_entries = entries;
        self
    }
}

/// Filter configuration for log queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    /// Filter by minimum log level
    pub min_level: Option<LogLevel>,
    /// Filter by exact log level
    pub level: Option<LogLevel>,
    /// Filter by keyword in message
    pub keyword: Option<String>,
    /// Filter by source
    pub source: Option<String>,
    /// Filter by user
    pub user: Option<String>,
    /// Filter by time range (start)
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by time range (end)
    pub end_time: Option<DateTime<Utc>>,
}

impl LogFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a log entry matches the filter
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Check minimum level
        if let Some(ref min_level) = self.min_level {
            if entry.level.priority() < min_level.priority() {
                return false;
            }
        }

        // Check exact level
        if let Some(ref level) = self.level {
            if entry.level != *level {
                return false;
            }
        }

        // Check keyword
        if let Some(ref keyword) = self.keyword {
            if !entry.contains_keyword(keyword) {
                return false;
            }
        }

        // Check source
        if let Some(ref source) = self.source {
            if entry.source.as_ref() != Some(source) {
                return false;
            }
        }

        // Check user
        if let Some(ref user) = self.user {
            if entry.user.as_ref() != Some(user) {
                return false;
            }
        }

        // Check time range
        if let Some(start) = self.start_time {
            if entry.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if entry.timestamp > end {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_string() {
        assert_eq!(LogLevel::from("ERROR"), LogLevel::Error);
        assert_eq!(LogLevel::from("error"), LogLevel::Error);
        assert_eq!(LogLevel::from("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from("WARNING"), LogLevel::Warn);
        assert_eq!(LogLevel::from("info"), LogLevel::Info);
        assert_eq!(LogLevel::from("debug"), LogLevel::Debug);
        assert_eq!(LogLevel::from("trace"), LogLevel::Trace);
        assert_eq!(LogLevel::from("unknown"), LogLevel::Unknown);
    }

    #[test]
    fn test_log_entry_contains_keyword() {
        let entry = LogEntry::new(
            LogLevel::Info,
            "User login successful".to_string(),
            "INFO: User login successful".to_string(),
            "/var/log/app.log".to_string(),
        );
        assert!(entry.contains_keyword("login"));
        assert!(entry.contains_keyword("USER"));
        assert!(!entry.contains_keyword("logout"));
    }

    #[test]
    fn test_statistics_update() {
        let mut stats = Statistics::new();
        let entry = LogEntry::new(
            LogLevel::Error,
            "Test error".to_string(),
            "ERROR: Test error".to_string(),
            "/var/log/app.log".to_string(),
        );
        stats.update(&entry);
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.get_level_count(&LogLevel::Error), 1);
        assert_eq!(stats.error_rate(), 1.0);
    }

    #[test]
    fn test_log_filter_matches() {
        let entry = LogEntry::new(
            LogLevel::Error,
            "Database connection failed".to_string(),
            "ERROR: Database connection failed".to_string(),
            "/var/log/app.log".to_string(),
        );

        let filter = LogFilter {
            level: Some(LogLevel::Error),
            keyword: Some("database"),
            ..Default::default()
        };

        assert!(filter.matches(&entry));

        let wrong_level_filter = LogFilter {
            level: Some(LogLevel::Info),
            ..Default::default()
        };
        assert!(!wrong_level_filter.matches(&entry));
    }
}
