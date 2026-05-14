//! Log analyzer core module with streaming and parallel processing

use crate::config::{Config, Rule, RuleAction, RuleCondition};
use crate::error::{LogAnalyzerError, Result};
use crate::models::{Anomaly, AnomalyType, LogEntry, LogLevel, Severity, Statistics};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Main log analyzer structure
pub struct LogAnalyzer {
    /// Configuration
    config: Config,
    /// Compiled regex patterns for rules
    rule_patterns: DashMap<String, Regex>,
    /// Statistics (thread-safe)
    statistics: Arc<DashMap<String, Statistics>>,
    /// Detected anomalies (thread-safe)
    anomalies: Arc<DashMap<String, Vec<Anomaly>>>,
    /// Active log files being watched
    watched_files: Arc<DashMap<PathBuf, Arc<AtomicBool>>>,
    /// Channel sender for log entries
    log_sender: broadcast::Sender<LogEntry>,
    /// Channel sender for anomalies
    anomaly_sender: broadcast::Sender<Anomaly>,
    /// Worker handles
    workers: Vec<JoinHandle<()>>,
    /// File watcher
    watcher: Option<RecommendedWatcher>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Total processed count
    processed_count: Arc<AtomicU64>,
}

impl LogAnalyzer {
    /// Create a new log analyzer with the given configuration
    pub fn new(config: Config, num_workers: usize) -> Self {
        let (log_tx, _) = broadcast::channel(1000);
        let (anomaly_tx, _) = broadcast::channel(100);
        
        let mut analyzer = Self {
            config,
            rule_patterns: DashMap::new(),
            statistics: Arc::new(DashMap::new()),
            anomalies: Arc::new(DashMap::new()),
            watched_files: Arc::new(DashMap::new()),
            log_sender: log_tx,
            anomaly_sender: anomaly_tx,
            workers: Vec::new(),
            watcher: None,
            running: Arc::new(AtomicBool::new(false)),
            processed_count: Arc::new(AtomicU64::new(0)),
        };

        // Compile regex patterns for rules
        analyzer.compile_rule_patterns();

        analyzer
    }

    /// Compile regex patterns from rules
    fn compile_rule_patterns(&mut self) {
        for rule in &self.config.rules {
            if let RuleCondition::Pattern(pattern) = &rule.condition {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        self.rule_patterns.insert(rule.id.clone(), regex);
                        info!("Compiled regex pattern for rule: {}", rule.id);
                    }
                    Err(e) => {
                        error!("Failed to compile regex for rule {}: {}", rule.id, e);
                    }
                }
            }
        }
    }

    /// Add a log file to be monitored
    pub fn add_log_file(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(LogAnalyzerError::FileNotFound(
                path.display().to_string(),
            ));
        }

        let path_buf = path.to_path_buf();
        let stop_flag = Arc::new(AtomicBool::new(false));
        self.watched_files.insert(path_buf.clone(), stop_flag);

        info!("Added log file for monitoring: {:?}", path);
        Ok(())
    }

    /// Remove a log file from monitoring
    pub fn remove_log_file(&self, path: &Path) -> Result<()> {
        if let Some((_, stop_flag)) = self.watched_files.remove(path) {
            stop_flag.store(true, Ordering::Relaxed);
            info!("Removed log file from monitoring: {:?}", path);
            Ok(())
        } else {
            Err(LogAnalyzerError::FileNotFound(
                path.display().to_string(),
            ))
        }
    }

    /// Start the analyzer with worker threads
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(LogAnalyzerError::AnomalyDetection(
                "Analyzer is already running".to_string(),
            ));
        }

        self.running.store(true, Ordering::Relaxed);

        // Start file watchers
        self.start_file_watchers()?;

        // Start worker threads
        self.start_workers();

        // Start anomaly detection task
        self.start_anomaly_detection();

        info!("Log analyzer started with {} workers", self.workers.len());
        Ok(())
    }

    /// Stop the analyzer and all workers
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.running.store(false, Ordering::Relaxed);

        // Signal all file watchers to stop
        for (_, stop_flag) in self.watched_files.iter() {
            stop_flag.store(true, Ordering::Relaxed);
        }

        // Wait for workers to finish
        for handle in self.workers.drain(..) {
            let _ = handle.await;
        }

        info!("Log analyzer stopped");
        Ok(())
    }

    /// Start file watchers using notify crate
    fn start_file_watchers(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(100);
        
        let mut watcher = recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })?;

        // Watch all added files
        for (path, _) in self.watched_files.iter() {
            watcher.watch(path, RecursiveMode::NonRecursive)?;
            debug!("Watching file: {:?}", path);
        }

        self.watcher = Some(watcher);

        // Spawn task to handle file events
        let watched_files = self.watched_files.clone();
        let log_sender = self.log_sender.clone();
        let running = self.running.clone();
        let processed_count = self.processed_count.clone();

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                if let Some(event) = rx.recv().await {
                    for path in event.paths {
                        if let Some(stop_flag) = watched_files.get(&path) {
                            if stop_flag.load(Ordering::Relaxed) {
                                continue;
                            }
                            
                            // Read new lines from the file
                            if let Ok(entries) = read_new_lines(&path) {
                                for entry in entries {
                                    processed_count.fetch_add(1, Ordering::Relaxed);
                                    let _ = log_sender.send(entry);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Start worker tasks for parallel log processing
    fn start_workers(&mut self) {
        let num_workers = self.config.workers;
        let mut log_receiver = self.log_sender.subscribe();
        let statistics = self.statistics.clone();
        let anomalies = self.anomalies.clone();
        let anomaly_sender = self.anomaly_sender.clone();
        let rules = self.config.rules.clone();
        let rule_patterns = self.rule_patterns.clone();
        let running = self.running.clone();

        for i in 0..num_workers {
            let mut rx = log_receiver.resubscribe();
            let stats = statistics.clone();
            let anoms = anomalies.clone();
            let anom_tx = anomaly_sender.clone();
            let worker_rules = rules.clone();
            let patterns = rule_patterns.clone();
            let worker_running = running.clone();

            let handle = tokio::spawn(async move {
                info!("Worker {} started", i);
                
                while worker_running.load(Ordering::Relaxed) {
                    match rx.recv().await {
                        Ok(entry) => {
                            // Process the log entry
                            process_log_entry(
                                entry,
                                &worker_rules,
                                &patterns,
                                &stats,
                                &anoms,
                                &anom_tx,
                            );
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Worker {} lagged behind, missed {} messages", i, n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                
                info!("Worker {} stopped", i);
            });

            self.workers.push(handle);
        }
    }

    /// Start anomaly detection background task
    fn start_anomaly_detection(&self) {
        let statistics = self.statistics.clone();
        let anomaly_sender = self.anomaly_sender.clone();
        let config = self.config.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                config.time_window_seconds,
            ));

            let mut prev_counts: DashMap<String, u64> = DashMap::new();

            while running.load(Ordering::Relaxed) {
                interval.tick().await;

                // Check for error spikes
                let mut total_errors = 0u64;
                for stats_ref in statistics.iter() {
                    let stats = stats_ref.value();
                    let errors = stats.get_level_count(&LogLevel::Error);
                    total_errors += errors;
                }

                if total_errors > config.error_threshold as u64 {
                    let anomaly = Anomaly {
                        anomaly_type: AnomalyType::ErrorSpike,
                        description: format!(
                            "Error count ({}) exceeded threshold ({}) in last {} seconds",
                            total_errors, config.error_threshold, config.time_window_seconds
                        ),
                        detected_at: Utc::now(),
                        severity: Severity::High,
                        related_entries: Vec::new(),
                    };

                    let _ = anomaly_sender.send(anomaly);
                }

                // Check for volume spikes
                let mut total_current = 0u64;
                for stats_ref in statistics.iter() {
                    total_current += stats_ref.value().total_entries;
                }

                let prev_total: u64 = prev_counts.sum(|v| *v.value());
                if prev_total > 0 {
                    let ratio = total_current as f64 / prev_total as f64;
                    if ratio > config.volume_threshold {
                        let anomaly = Anomaly {
                            anomaly_type: AnomalyType::VolumeSpike,
                            description: format!(
                                "Log volume increased by {:.2}x (threshold: {:.2}x)",
                                ratio, config.volume_threshold
                            ),
                            detected_at: Utc::now(),
                            severity: Severity::Medium,
                            related_entries: Vec::new(),
                        };

                        let _ = anomaly_sender.send(anomaly);
                    }
                }

                // Update previous counts
                prev_counts.clear();
                for stats_ref in statistics.iter() {
                    prev_counts.insert(stats_ref.key().clone(), stats_ref.value().total_entries);
                }
            }
        });
    }

    /// Get current statistics
    pub fn get_statistics(&self) -> Vec<(String, Statistics)> {
        self.statistics
            .iter()
            .map(|ref_multi| (ref_multi.key().clone(), ref_multi.value().clone()))
            .collect()
    }

    /// Get detected anomalies
    pub fn get_anomalies(&self) -> Vec<(String, Vec<Anomaly>)> {
        self.anomalies
            .iter()
            .map(|ref_multi| (ref_multi.key().clone(), ref_multi.value().clone()))
            .collect()
    }

    /// Get total processed count
    pub fn get_processed_count(&self) -> u64 {
        self.processed_count.load(Ordering::Relaxed)
    }

    /// Subscribe to log entries
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEntry> {
        self.log_sender.subscribe()
    }

    /// Subscribe to anomalies
    pub fn subscribe_anomalies(&self) -> broadcast::Receiver<Anomaly> {
        self.anomaly_sender.subscribe()
    }
}

/// Process a single log entry against rules
fn process_log_entry(
    entry: LogEntry,
    rules: &[Rule],
    patterns: &DashMap<String, Regex>,
    statistics: &Arc<DashMap<String, Statistics>>,
    anomalies: &Arc<DashMap<String, Vec<Anomaly>>>,
    anomaly_sender: &broadcast::Sender<Anomaly>,
) {
    // Update statistics
    let file_key = entry.file_path.clone();
    if let mut stats = statistics.get_mut(&file_key) {
        stats.update(&entry);
    } else {
        let mut stats = Statistics::new();
        stats.update(&entry);
        statistics.insert(file_key.clone(), stats);
    }

    // Check against rules
    for rule in rules {
        if !rule.enabled {
            continue;
        }

        let matches = match &rule.condition {
            RuleCondition::Level(level) => entry.level == *level,
            RuleCondition::Keyword(keyword) => entry.contains_keyword(keyword),
            RuleCondition::Source(source) => {
                entry.source.as_ref().map_or(false, |s| s == source)
            }
            RuleCondition::Pattern(_) => {
                if let Some(regex) = patterns.get(&rule.id) {
                    regex.is_match(&entry.message) || regex.is_match(&entry.raw_line)
                } else {
                    false
                }
            }
            RuleCondition::ErrorThreshold { .. } => {
                entry.level == LogLevel::Error
            }
            RuleCondition::All => true,
        };

        if matches {
            match &rule.action {
                RuleAction::Count => {
                    // Already counted in statistics
                }
                RuleAction::Warn { severity } => {
                    let sev = match severity.to_lowercase().as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        _ => Severity::Low,
                    };

                    let anomaly = Anomaly {
                        anomaly_type: AnomalyType::RuleViolation,
                        description: format!("Rule '{}' triggered: {}", rule.name, entry.message),
                        detected_at: Utc::now(),
                        severity: sev,
                        related_entries: vec![entry.clone()],
                    };

                    let _ = anomaly_sender.send(anomaly);
                }
                RuleAction::Ignore => {
                    // Skip further processing
                    break;
                }
                RuleAction::Tag { .. } => {
                    // Tagging logic would go here
                }
                RuleAction::Forward { .. } => {
                    // Forwarding logic would go here
                }
            }
        }
    }
}

/// Read new lines from a log file (tail-like behavior)
fn read_new_lines(path: &Path) -> Result<Vec<LogEntry>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    // Seek to end to get current position
    let _ = reader.seek(SeekFrom::End(0));
    
    // In a real implementation, we would track the last read position
    // For now, we'll read the last N lines as a demonstration
    let mut entries = Vec::new();
    
    // Read entire file (in production, this would be optimized)
    let mut lines = Vec::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(l) = line {
            lines.push(l);
        }
    }
    
    // Parse last few lines
    for line in lines.iter().rev().take(10).rev() {
        if let Some(entry) = parse_log_line(line, path.to_string_lossy().to_string()) {
            entries.push(entry);
        }
    }
    
    Ok(entries)
}

/// Parse a log line into a LogEntry
fn parse_log_line(line: &str, file_path: String) -> Option<LogEntry> {
    // Simple log parsing - can be enhanced based on requirements
    // Expected format: [LEVEL] message or LEVEL: message
    
    let (level, message) = if let Some(idx) = line.find(']') {
        // Format: [LEVEL] message
        let level_str = &line[1..idx];
        let msg = line[idx + 1..].trim().to_string();
        (LogLevel::from(level_str), msg)
    } else if let Some(idx) = line.find(':') {
        // Format: LEVEL: message
        let level_str = &line[..idx];
        let msg = line[idx + 1..].trim().to_string();
        (LogLevel::from(level_str), msg)
    } else {
        // Unknown format, treat as INFO
        (LogLevel::Info, line.to_string())
    };

    Some(LogEntry::new(level, message, line.to_string(), file_path))
}

impl Drop for LogAnalyzer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
