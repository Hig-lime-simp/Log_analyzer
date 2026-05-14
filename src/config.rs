//! Configuration module for log analyzer

use crate::error::{LogAnalyzerError, Result};
use crate::models::LogLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Analysis rules
    #[serde(default)]
    pub rules: Vec<Rule>,
    
    /// Number of worker threads
    #[serde(default = "default_workers")]
    pub workers: usize,
    
    /// Time window for anomaly detection (in seconds)
    #[serde(default = "default_time_window")]
    pub time_window_seconds: u64,
    
    /// Error threshold for anomaly detection
    #[serde(default = "default_error_threshold")]
    pub error_threshold: u32,
    
    /// Volume spike threshold (multiplier)
    #[serde(default = "default_volume_threshold")]
    pub volume_threshold: f64,
    
    /// Output settings
    #[serde(default)]
    pub output: OutputConfig,
}

fn default_workers() -> usize {
    4
}

fn default_time_window() -> u64 {
    60
}

fn default_error_threshold() -> u32 {
    10
}

fn default_volume_threshold() -> f64 {
    2.0
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            workers: default_workers(),
            time_window_seconds: default_time_window(),
            error_threshold: default_error_threshold(),
            volume_threshold: default_volume_threshold(),
            output: OutputConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a file (supports JSON, TOML)
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(LogAnalyzerError::FileNotFound(
                path.display().to_string(),
            ));
        }

        let content = fs::read_to_string(path)?;
        let extension = path.extension().and_then(|e| e.to_str());

        match extension {
            Some("json") => Ok(serde_json::from_str(&content)?),
            Some("toml") => Ok(toml::from_str(&content)?),
            Some("yaml") | Some("yml") => {
                // YAML support would require serde_yaml crate
                Err(LogAnalyzerError::Config(
                    "YAML format requires additional dependencies".to_string(),
                ))
            }
            _ => Err(LogAnalyzerError::Config(format!(
                "Unsupported configuration format: {:?}",
                extension
            ))),
        }
    }

    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let extension = path.extension().and_then(|e| e.to_str());
        let content = match extension {
            Some("json") => serde_json::to_string_pretty(self)?,
            Some("toml") => toml::to_string_pretty(self)?,
            _ => return Err(LogAnalyzerError::Config(
                "Unsupported configuration format".to_string(),
            )),
        };

        fs::write(path, content)?;
        Ok(())
    }
}

/// Analysis rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    
    /// Rule name/description
    pub name: String,
    
    /// Condition type
    pub condition: RuleCondition,
    
    /// Log format pattern (regex)
    #[serde(default)]
    pub log_format: Option<String>,
    
    /// Action to take when rule matches
    pub action: RuleAction,
    
    /// Priority (lower number = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u32,
    
    /// Enabled status
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

/// Types of conditions that can be checked
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RuleCondition {
    /// Match by log level
    Level(LogLevel),
    
    /// Match by keyword in message
    Keyword(String),
    
    /// Match by source
    Source(String),
    
    /// Match by regex pattern
    Pattern(String),
    
    /// Match if error count exceeds threshold in time window
    ErrorThreshold { count: u32, window_seconds: u64 },
    
    /// Match all (catch-all)
    All,
}

/// Actions that can be taken when a rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum RuleAction {
    /// Count the matching entry
    Count,
    
    /// Generate a warning/alert
    Warn { severity: String },
    
    /// Ignore the entry (skip processing)
    Ignore,
    
    /// Tag the entry with metadata
    Tag { tags: Vec<String> },
    
    /// Forward to external system
    Forward { endpoint: String },
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Enable console output
    #[serde(default = "default_true")]
    pub console: bool,
    
    /// Path to report file (if any)
    #[serde(default)]
    pub report_file: Option<String>,
    
    /// Report format
    #[serde(default)]
    pub report_format: ReportFormat,
    
    /// Enable real-time updates in TUI
    #[serde(default = "default_true")]
    pub realtime: bool,
}

fn default_true() -> bool {
    true
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            console: true,
            report_file: None,
            report_format: ReportFormat::default(),
            realtime: true,
        }
    }
}

/// Report output formats
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ReportFormat {
    #[default]
    Json,
    Text,
    Csv,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout in seconds
    #[serde(default = "default_session_timeout")]
    pub timeout_seconds: u64,
    
    /// Maximum sessions allowed
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    
    /// Persist sessions to disk
    #[serde(default)]
    pub persist: bool,
    
    /// Session storage directory
    #[serde(default)]
    pub storage_dir: Option<String>,
}

fn default_session_timeout() -> u64 {
    3600
}

fn default_max_sessions() -> usize {
    10
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_session_timeout(),
            max_sessions: default_max_sessions(),
            persist: false,
            storage_dir: None,
        }
    }
}
