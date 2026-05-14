//! Session management module

use crate::error::{LogAnalyzerError, Result};
use crate::models::{Anomaly, LogEntry, Statistics};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Session manager for handling multiple analysis sessions
pub struct SessionManager {
    /// Active sessions
    sessions: HashMap<String, Session>,
    /// Session storage directory
    storage_dir: Option<PathBuf>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            storage_dir: None,
        }
    }

    /// Set the storage directory for session persistence
    pub fn with_storage_dir(mut self, dir: &Path) -> Self {
        self.storage_dir = Some(dir.to_path_buf());
        if let Some(ref d) = self.storage_dir {
            let _ = fs::create_dir_all(d);
        }
        self
    }

    /// Create a new session
    pub fn create_session(&mut self) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let session = Session::new(session_id.clone());
        
        self.sessions.insert(session_id.clone(), session);
        
        // Persist if storage is configured
        if let Some(ref dir) = self.storage_dir {
            self.save_session_to_disk(&session_id, dir)?;
        }

        Ok(session_id)
    }

    /// Restore a session from disk
    pub fn restore_session(&mut self, session_id: &str) -> Result<()> {
        if self.sessions.contains_key(session_id) {
            return Ok(());
        }

        if let Some(ref dir) = self.storage_dir {
            let session_path = dir.join(format!("{}.json", session_id));
            if session_path.exists() {
                let content = fs::read_to_string(&session_path)?;
                let session: Session = serde_json::from_str(&content)?;
                self.sessions.insert(session_id.to_string(), session);
                return Ok(());
            }
        }

        Err(LogAnalyzerError::Session(format!(
            "Session '{}' not found",
            session_id
        )))
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    /// Get a mutable reference to a session
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &str) -> Result<()> {
        if self.sessions.remove(session_id).is_some() {
            // Remove from disk if persisted
            if let Some(ref dir) = self.storage_dir {
                let session_path = dir.join(format!("{}.json", session_id));
                if session_path.exists() {
                    let _ = fs::remove_file(&session_path);
                }
            }
            Ok(())
        } else {
            Err(LogAnalyzerError::Session(format!(
                "Session '{}' not found",
                session_id
            )))
        }
    }

    /// List all active session IDs
    pub fn list_sessions(&self) -> Vec<&String> {
        self.sessions.keys().collect()
    }

    /// Save a session to disk
    fn save_session_to_disk(&self, session_id: &str, dir: &Path) -> Result<()> {
        if let Some(session) = self.sessions.get(session_id) {
            let session_path = dir.join(format!("{}.json", session_id));
            let content = serde_json::to_string_pretty(session)?;
            fs::write(&session_path, content)?;
        }
        Ok(())
    }

    /// Save all sessions to disk
    pub fn save_all_sessions(&self) -> Result<()> {
        if let Some(ref dir) = self.storage_dir {
            for session_id in self.sessions.keys() {
                self.save_session_to_disk(session_id, dir)?;
            }
        }
        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an analysis session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// List of monitored files
    pub monitored_files: Vec<PathBuf>,
    /// Applied filters
    pub filters: SessionFilters,
    /// Session statistics snapshot
    pub statistics: HashMap<String, Statistics>,
    /// Detected anomalies
    pub anomalies: Vec<Anomaly>,
    /// Recent log entries (circular buffer)
    pub recent_logs: Vec<LogEntry>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

impl Session {
    /// Create a new session with the given ID
    pub fn new(id: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            created_at: now,
            last_activity: now,
            monitored_files: Vec::new(),
            filters: SessionFilters::default(),
            statistics: HashMap::new(),
            anomalies: Vec::new(),
            recent_logs: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Add a file to monitoring list
    pub fn add_monitored_file(&mut self, path: PathBuf) {
        if !self.monitored_files.contains(&path) {
            self.monitored_files.push(path);
            self.touch();
        }
    }

    /// Remove a file from monitoring list
    pub fn remove_monitored_file(&mut self, path: &Path) {
        self.monitored_files.retain(|p| p != path);
        self.touch();
    }

    /// Add a log entry to recent logs (with circular buffer behavior)
    pub fn add_recent_log(&mut self, entry: LogEntry, max_size: usize) {
        if self.recent_logs.len() >= max_size {
            self.recent_logs.remove(0);
        }
        self.recent_logs.push(entry);
        self.touch();
    }

    /// Add an anomaly to the session
    pub fn add_anomaly(&mut self, anomaly: Anomaly) {
        self.anomalies.push(anomaly);
        self.touch();
    }

    /// Update statistics for a file
    pub fn update_statistics(&mut self, file_path: String, stats: Statistics) {
        self.statistics.insert(file_path, stats);
        self.touch();
    }

    /// Get session duration
    pub fn duration(&self) -> chrono::Duration {
        self.last_activity - self.created_at
    }

    /// Get session info as string
    pub fn info(&self) -> String {
        format!(
            "Session {} (created: {}, files: {}, logs: {}, anomalies: {})",
            self.id,
            self.created_at.format("%Y-%m-%d %H:%M:%S"),
            self.monitored_files.len(),
            self.recent_logs.len(),
            self.anomalies.len()
        )
    }
}

/// Session-specific filters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionFilters {
    /// Filter by log levels
    pub levels: Vec<crate::models::LogLevel>,
    /// Filter by keyword
    pub keyword: Option<String>,
    /// Filter by source
    pub source: Option<String>,
    /// Minimum severity for anomalies
    pub min_severity: Option<crate::models::Severity>,
}

impl SessionFilters {
    /// Create new empty filters
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if filters are empty (no filtering)
    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
            && self.keyword.is_none()
            && self.source.is_none()
            && self.min_severity.is_none()
    }
}
