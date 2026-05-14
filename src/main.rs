//! Log Analyzer - Real-time log streaming and analysis CLI application
//! 
//! This application provides real-time log analysis with TUI interface,
//! supporting multiple log files, filtering, anomaly detection, and session management.

pub mod models;
pub mod config;
pub mod analyzer;
pub mod ui;
pub mod session;
pub mod error;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{self, EnvFilter};

use crate::config::Config;
use crate::session::SessionManager;
use crate::analyzer::LogAnalyzer;
use crate::ui::TuiApp;

/// CLI argument parser
#[derive(Parser, Debug)]
#[command(name = "log-analyzer")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "Real-time log analysis with TUI interface", long_about = None)]
pub struct Args {
    /// Path to configuration file (JSON, YAML, or TOML)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Log files to analyze
    #[arg(required = false)]
    pub files: Vec<PathBuf>,

    /// Session ID to restore (optional)
    #[arg(short, long)]
    pub session: Option<String>,

    /// Number of worker threads for parallel processing
    #[arg(short, long, default_value = "4")]
    pub workers: usize,

    /// Output report file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        Config::load(config_path)?
    } else {
        Config::default()
    };

    // Initialize session manager
    let mut session_manager = SessionManager::new();

    // Restore session if specified
    let session_id = if let Some(ref sid) = args.session {
        session_manager.restore_session(sid)?;
        sid.clone()
    } else {
        // Create new session
        session_manager.create_session()?
    };

    println!("Starting log analyzer with session: {}", session_id);
    println!("Configuration loaded: {} rules", config.rules.len());
    println!("Workers: {}", args.workers);

    // Initialize the log analyzer
    let analyzer = LogAnalyzer::new(config, args.workers);

    // Add log files to analyze
    for file_path in &args.files {
        analyzer.add_log_file(file_path)?;
        println!("Added log file: {:?}", file_path);
    }

    // Start the TUI application
    let mut app = TuiApp::new(analyzer, session_manager, args.output)?;
    app.run().await?;

    Ok(())
}
