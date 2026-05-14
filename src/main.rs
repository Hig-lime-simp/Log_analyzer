//! Log Analyzer - Real-time streaming log analysis CLI application
//! 
//! This application provides real-time log analysis with:
//! - Streaming processing of log files (tail-like behavior)
//! - Multi-threaded parallel processing with configurable workers
//! - Anomaly detection (error spikes, volume spikes, repeated events)
//! - TUI interface using Ratatui
//! - Session management with persistence
//! - Configurable rules via JSON/TOML configuration files

mod analyzer;
mod config;
mod error;
mod models;
mod session;
mod ui;

use crate::analyzer::LogAnalyzer;
use crate::config::Config;
use crate::error::{LogAnalyzerError, Result};
use crate::session::SessionManager;
use crate::ui::TuiApp;
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Command-line arguments for the log analyzer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (JSON or TOML)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Log files to analyze (can specify multiple)
    #[arg(value_name = "LOG_FILE")]
    log_files: Vec<PathBuf>,

    /// Output report file path (optional)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Number of worker threads (overrides config)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Session storage directory (for persistence)
    #[arg(long, value_name = "DIR")]
    session_dir: Option<PathBuf>,

    /// Restore a previous session by ID
    #[arg(long, value_name = "SESSION_ID")]
    restore_session: Option<String>,

    /// Subcommands for additional operations
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Additional subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Show current statistics without starting TUI
    Stats {
        /// Log files to analyze
        #[arg(value_name = "LOG_FILE")]
        log_files: Vec<PathBuf>,

        /// Configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Validate a configuration file
    Validate {
        /// Configuration file to validate
        #[arg(value_name = "CONFIG_FILE")]
        config_file: PathBuf,
    },

    /// List available sessions
    ListSessions {
        /// Session storage directory
        #[arg(long, value_name = "DIR")]
        session_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging/tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    // Handle subcommands
    if let Some(cmd) = args.command {
        return handle_command(cmd).await;
    }

    // Load configuration
    let config = load_config(args.config.as_deref())?;
    
    // Determine number of workers
    let num_workers = args.workers.unwrap_or(config.workers);

    // Create analyzer
    let mut analyzer = LogAnalyzer::new(config, num_workers);

    // Add log files
    for log_file in &args.log_files {
        analyzer.add_log_file(log_file)?;
        info!("Added log file: {:?}", log_file);
    }

    if args.log_files.is_empty() {
        eprintln!("Warning: No log files specified. Use --help for usage.");
        eprintln!("Usage: log-analyzer [OPTIONS] [LOG_FILE]...");
        return Ok(());
    }

    // Create session manager
    let mut session_manager = SessionManager::new();
    
    // Configure session storage if specified
    if let Some(ref dir) = args.session_dir {
        session_manager = session_manager.with_storage_dir(dir);
        info!("Session storage configured: {:?}", dir);
    }

    // Restore session if requested
    if let Some(ref session_id) = args.restore_session {
        session_manager.restore_session(session_id)?;
        info!("Restored session: {}", session_id);
    }

    // Create and run TUI application
    let mut app = TuiApp::new(analyzer, session_manager, args.output)?;
    
    println!("Starting Log Analyzer TUI...");
    println!("Press 'q' to quit, Tab to switch views, ↑↓ to scroll");
    println!();

    app.run().await?;

    Ok(())
}

/// Handle subcommands
async fn handle_command(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Stats { log_files, config } => {
            handle_stats_command(log_files, config).await?;
        }
        Commands::Validate { config_file } => {
            handle_validate_command(config_file)?;
        }
        Commands::ListSessions { session_dir } => {
            handle_list_sessions_command(session_dir)?;
        }
    }
    Ok(())
}

/// Handle the 'stats' subcommand
async fn handle_stats_command(log_files: Vec<PathBuf>, config_path: Option<PathBuf>) -> Result<()> {
    if log_files.is_empty() {
        return Err(LogAnalyzerError::Config(
            "No log files specified".to_string(),
        ));
    }

    let config = load_config(config_path.as_deref())?;
    let analyzer = LogAnalyzer::new(config, 2);

    // Add files
    for file in &log_files {
        analyzer.add_log_file(file)?;
    }

    // Start analyzer briefly to process logs
    let mut analyzer_mut = analyzer;
    analyzer_mut.start().await?;

    // Wait a bit for processing
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Stop and get statistics
    analyzer_mut.stop().await?;

    // Print statistics
    println!("\n=== Log Analysis Statistics ===\n");
    
    let stats = analyzer_mut.get_statistics();
    for (file_path, stat) in &stats {
        println!("File: {}", file_path);
        println!("  Total entries: {}", stat.total_entries);
        println!("  ERROR: {}", stat.get_level_count(&models::LogLevel::Error));
        println!("  WARN:  {}", stat.get_level_count(&models::LogLevel::Warn));
        println!("  INFO:  {}", stat.get_level_count(&models::LogLevel::Info));
        println!("  Error rate: {:.2}%", stat.error_rate() * 100.0);
        
        if !stat.source_counts.is_empty() {
            println!("  Top sources:");
            for (source, count) in stat.top_sources(3) {
                println!("    - {}: {}", source, count);
            }
        }
        println!();
    }

    println!("Total processed: {}", analyzer_mut.get_processed_count());

    Ok(())
}

/// Handle the 'validate' subcommand
fn handle_validate_command(config_file: PathBuf) -> Result<()> {
    if !config_file.exists() {
        return Err(LogAnalyzerError::FileNotFound(
            config_file.display().to_string(),
        ));
    }

    match Config::load(&config_file) {
        Ok(config) => {
            println!("✓ Configuration file is valid!");
            println!("\nConfiguration summary:");
            println!("  Rules: {}", config.rules.len());
            println!("  Workers: {}", config.workers);
            println!("  Time window: {} seconds", config.time_window_seconds);
            println!("  Error threshold: {}", config.error_threshold);
            println!("  Volume threshold: {:.2}x", config.volume_threshold);
            
            if !config.rules.is_empty() {
                println!("\nRules:");
                for rule in &config.rules {
                    let status = if rule.enabled { "✓" } else { "✗" };
                    println!("  {} [{}] {} (priority: {})", 
                        status, rule.id, rule.name, rule.priority);
                }
            }
            
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration file is invalid: {}", e);
            Err(e)
        }
    }
}

/// Handle the 'list-sessions' subcommand
fn handle_list_sessions_command(session_dir: Option<PathBuf>) -> Result<()> {
    let dir = session_dir.unwrap_or_else(|| PathBuf::from("./sessions"));
    
    if !dir.exists() {
        println!("No sessions found (directory does not exist: {:?})", dir);
        return Ok(());
    }

    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            sessions.push(path);
        }
    }

    if sessions.is_empty() {
        println!("No sessions found in {:?}", dir);
    } else {
        println!("Found {} session(s) in {:?}:\n", sessions.len(), dir);
        for path in &sessions {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                println!("  - {}", stem);
            }
        }
    }

    Ok(())
}

/// Load configuration from file or use defaults
fn load_config(config_path: Option<&Path>) -> anyhow::Result<Config> {
    if let Some(path) = config_path {
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Configuration file not found: {:?}",
                path
            ));
        }

        Config::load(path)
            .with_context(|| format!("Failed to load configuration from {:?}", path))
    } else {
        // Try to load default config files
        let default_paths = [
            PathBuf::from("log-config.json"),
            PathBuf::from("log-config.toml"),
            PathBuf::from("config.json"),
            PathBuf::from("config.toml"),
        ];

        for path in &default_paths {
            if path.exists() {
                info!("Loading configuration from {:?}", path);
                return Config::load(path)
                    .with_context(|| format!("Failed to load configuration from {:?}", path));
            }
        }

        // Use default configuration
        info!("Using default configuration");
        Ok(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.workers, 4);
        assert_eq!(config.time_window_seconds, 60);
        assert_eq!(config.error_threshold, 10);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_log_level_parsing() {
        use crate::models::LogLevel;
        
        assert_eq!(LogLevel::from("ERROR"), LogLevel::Error);
        assert_eq!(LogLevel::from("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from("INFO"), LogLevel::Info);
        assert_eq!(LogLevel::from("unknown_level"), LogLevel::Unknown);
    }
}
