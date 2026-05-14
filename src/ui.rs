//! TUI (Text User Interface) module using Ratatui

use crate::analyzer::LogAnalyzer;
use crate::models::{Anomaly, LogEntry, LogLevel, Severity};
use crate::session::SessionManager;
use anyhow::Result;
use chrono::Utc;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::error;

/// Main TUI application state
pub struct TuiApp {
    /// Log analyzer instance
    analyzer: LogAnalyzer,
    /// Session manager
    session_manager: SessionManager,
    /// Current session ID
    session_id: String,
    /// Recent log entries (circular buffer)
    recent_logs: Vec<LogEntry>,
    /// Detected anomalies
    anomalies: Vec<Anomaly>,
    /// Current filter keyword
    filter_keyword: Option<String>,
    /// Selected log level filter
    selected_level: Option<LogLevel>,
    /// Output report file path
    output_file: Option<PathBuf>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Scroll offset for logs view
    scroll_offset: usize,
    /// Active tab (0: Logs, 1: Statistics, 2: Anomalies)
    active_tab: usize,
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new(
        analyzer: LogAnalyzer,
        mut session_manager: SessionManager,
        output_file: Option<PathBuf>,
    ) -> Result<Self> {
        let session_id = session_manager.create_session()?;
        
        Ok(Self {
            analyzer,
            session_manager,
            session_id,
            recent_logs: Vec::with_capacity(100),
            anomalies: Vec::new(),
            filter_keyword: None,
            selected_level: None,
            output_file,
            running: Arc::new(AtomicBool::new(true)),
            scroll_offset: 0,
            active_tab: 0,
        })
    }

    /// Run the TUI application
    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Start the analyzer
        self.analyzer.start().await?;

        // Subscribe to log entries and anomalies
        let mut log_rx = self.analyzer.subscribe_logs();
        let mut anomaly_rx = self.analyzer.subscribe_anomalies();
        let running = self.running.clone();

        // Spawn task to receive log entries
        let logs_clone = Arc::new(std::sync::Mutex::new(Vec::new()));
        let anomalies_clone = Arc::new(std::sync::Mutex::new(Vec::new()));
        
        let logs_for_task = logs_clone.clone();
        let running_for_task = running.clone();
        tokio::spawn(async move {
            while running_for_task.load(Ordering::Relaxed) {
                match log_rx.recv().await {
                    Ok(entry) => {
                        if let Ok(mut logs) = logs_for_task.lock() {
                            logs.push(entry);
                            if logs.len() > 200 {
                                logs.remove(0);
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
        });

        let anomalies_for_task = anomalies_clone.clone();
        let running_for_task = running.clone();
        tokio::spawn(async move {
            while running_for_task.load(Ordering::Relaxed) {
                match anomaly_rx.recv().await {
                    Ok(anomaly) => {
                        if let Ok(mut anoms) = anomalies_for_task.lock() {
                            anoms.push(anomaly);
                            if anoms.len() > 50 {
                                anoms.remove(0);
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
        });

        // Main UI loop
        let result = self.ui_loop(&mut terminal, logs_clone, anomalies_clone).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        // Stop analyzer
        self.analyzer.stop().await?;

        // Save session
        self.session_manager.save_all_sessions()?;

        // Generate report if output file specified
        if let Some(ref path) = self.output_file {
            self.generate_report(path)?;
        }

        result
    }

    /// Main UI rendering loop
    async fn ui_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        logs_clone: Arc<std::sync::Mutex<Vec<LogEntry>>>,
        anomalies_clone: Arc<std::sync::Mutex<Vec<Anomaly>>>,
    ) -> Result<()> {
        loop {
            // Update logs from shared state
            if let Ok(logs) = logs_clone.lock() {
                self.recent_logs = logs.clone();
            }

            // Update anomalies from shared state
            if let Ok(anoms) = anomalies_clone.lock() {
                self.anomalies = anoms.clone();
            }

            // Render UI
            terminal.draw(|f| self.render(f))?;

            // Handle input events
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') => {
                                self.running.store(false, Ordering::Relaxed);
                                break;
                            }
                            KeyCode::Tab => {
                                self.active_tab = (self.active_tab + 1) % 3;
                            }
                            KeyCode::Up => {
                                if self.scroll_offset > 0 {
                                    self.scroll_offset -= 1;
                                }
                            }
                            KeyCode::Down => {
                                let max_scroll = self.recent_logs.len().saturating_sub(1);
                                if self.scroll_offset < max_scroll {
                                    self.scroll_offset += 1;
                                }
                            }
                            KeyCode::Char('/') => {
                                // Could implement search input here
                            }
                            KeyCode::Char('1') => self.active_tab = 0,
                            KeyCode::Char('2') => self.active_tab = 1,
                            KeyCode::Char('3') => self.active_tab = 2,
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Render the UI
    fn render(&mut self, f: &mut Frame<'_>) {
        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Length(3),  // Tabs
                Constraint::Min(0),     // Main content
                Constraint::Length(3),  // Footer/Status
            ])
            .split(f.size());

        // Render header
        self.render_header(f, chunks[0]);

        // Render tabs
        self.render_tabs(f, chunks[1]);

        // Render main content based on active tab
        match self.active_tab {
            0 => self.render_logs(f, chunks[2]),
            1 => self.render_statistics(f, chunks[2]),
            2 => self.render_anomalies(f, chunks[2]),
            _ => {}
        }

        // Render footer
        self.render_footer(f, chunks[3]);
    }

    /// Render header
    fn render_header(&self, f: &mut Frame<'_>, area: Rect) {
        let header = Paragraph::new(format!(
            "Log Analyzer - Session: {} | Files: {} | Processed: {}",
            self.session_id,
            self.recent_logs.iter().map(|e| e.file_path.clone()).collect::<std::collections::HashSet<_>>().len(),
            self.analyzer.get_processed_count()
        ))
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Header"));
        
        f.render_widget(header, area);
    }

    /// Render tabs
    fn render_tabs(&self, f: &mut Frame<'_>, area: Rect) {
        let tabs = vec![
            Span::styled("Logs (1)", self.tab_style(0)),
            Span::raw(" | "),
            Span::styled("Statistics (2)", self.tab_style(1)),
            Span::raw(" | "),
            Span::styled("Anomalies (3)", self.tab_style(2)),
        ];

        let tabs_text = Text::from(Line::from(tabs));
        let tabs_widget = Paragraph::new(tabs_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title("Navigation"));

        f.render_widget(tabs_widget, area);
    }

    /// Get style for tab based on active state
    fn tab_style(&self, tab_index: usize) -> Style {
        if self.active_tab == tab_index {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    }

    /// Render logs view
    fn render_logs(&mut self, f: &mut Frame<'_>, area: Rect) {
        // Apply filters
        let filtered_logs: Vec<&LogEntry> = self
            .recent_logs
            .iter()
            .filter(|entry| {
                // Level filter
                if let Some(ref level) = self.selected_level {
                    if entry.level != *level {
                        return false;
                    }
                }

                // Keyword filter
                if let Some(ref keyword) = self.filter_keyword {
                    if !entry.contains_keyword(keyword) {
                        return false;
                    }
                }

                true
            })
            .rev()
            .skip(self.scroll_offset)
            .take(area.height as usize - 2)
            .collect();

        // Create list items with color-coded levels
        let items: Vec<ListItem> = filtered_logs
            .iter()
            .map(|entry| {
                let level_color = match entry.level {
                    LogLevel::Error => Color::Red,
                    LogLevel::Warn => Color::Yellow,
                    LogLevel::Info => Color::Green,
                    LogLevel::Debug => Color::Blue,
                    LogLevel::Trace => Color::Magenta,
                    LogLevel::Unknown => Color::Gray,
                };

                let line = Line::from(vec![
                    Span::styled(
                        format!("[{}] ", entry.timestamp.format("%H:%M:%S")),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:<5} ", entry.level),
                        Style::default().fg(level_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(&entry.message),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Live Logs (showing {} of {})",
                filtered_logs.len(),
                self.recent_logs.len()
            )))
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    }

    /// Render statistics view
    fn render_statistics(&self, f: &mut Frame<'_>, area: Rect) {
        let stats = self.analyzer.get_statistics();
        
        let mut lines = Vec::new();
        
        for (file_path, stat) in &stats {
            lines.push(Line::from(Span::styled(
                format!("File: {}", file_path),
                Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
            )));
            
            lines.push(Line::from(format!("  Total entries: {}", stat.total_entries)));
            lines.push(Line::from(format!("  ERROR: {}", stat.get_level_count(&LogLevel::Error))));
            lines.push(Line::from(format!("  WARN:  {}", stat.get_level_count(&LogLevel::Warn))));
            lines.push(Line::from(format!("  INFO:  {}", stat.get_level_count(&LogLevel::Info))));
            lines.push(Line::from(format!("  Error rate: {:.2}%", stat.error_rate() * 100.0)));
            lines.push(Line::from(""));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Statistics"))
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
    }

    /// Render anomalies view
    fn render_anomalies(&self, f: &mut Frame<'_>, area: Rect) {
        let items: Vec<ListItem> = self
            .anomalies
            .iter()
            .rev()
            .map(|anomaly| {
                let severity_color = match anomaly.severity {
                    Severity::Critical => Color::Red,
                    Severity::High => Color::DarkRed,
                    Severity::Medium => Color::Yellow,
                    Severity::Low => Color::Blue,
                };

                let anomaly_type = match &anomaly.anomaly_type {
                    crate::models::AnomalyType::ErrorSpike => "ERROR SPIKE",
                    crate::models::AnomalyType::RepeatedEvent => "REPEATED",
                    crate::models::AnomalyType::VolumeSpike => "VOLUME",
                    crate::models::AnomalyType::RuleViolation => "RULE",
                };

                let line = Line::from(vec![
                    Span::styled(
                        format!("[{}] ", anomaly.detected_at.format("%H:%M:%S")),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:<12} ", anomaly_type),
                        Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("[{}] ", anomaly.severity),
                        Style::default().fg(severity_color),
                    ),
                    Span::raw(&anomaly.description),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Anomalies ({})",
                self.anomalies.len()
            )))
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    }

    /// Render footer
    fn render_footer(&self, f: &mut Frame<'_>, area: Rect) {
        let footer_text = if let Some(ref keyword) = self.filter_keyword {
            format!("Filter: '{}' | Press 'q' to quit, Tab to switch views", keyword)
        } else {
            "Press 'q' to quit, Tab to switch views, ↑↓ to scroll".to_string()
        };

        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title("Help"));

        f.render_widget(footer, area);
    }

    /// Generate report file
    fn generate_report(&self, path: &PathBuf) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(path)?;
        
        writeln!(file, "Log Analysis Report")?;
        writeln!(file, "==================")?;
        writeln!(file, "Generated: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(file, "Session: {}", self.session_id)?;
        writeln!(file)?;

        writeln!(file, "Summary")?;
        writeln!(file, "-------")?;
        writeln!(file, "Total processed: {}", self.analyzer.get_processed_count())?;
        writeln!(file, "Total anomalies: {}", self.anomalies.len())?;
        writeln!(file)?;

        writeln!(file, "Statistics by File")?;
        writeln!(file, "------------------")?;
        for (file_path, stat) in self.analyzer.get_statistics() {
            writeln!(file, "File: {}", file_path)?;
            writeln!(file, "  Total: {}", stat.total_entries)?;
            writeln!(file, "  Errors: {}", stat.get_level_count(&LogLevel::Error))?;
            writeln!(file, "  Warnings: {}", stat.get_level_count(&LogLevel::Warn))?;
            writeln!(file, "  Error rate: {:.2}%", stat.error_rate() * 100.0)?;
            writeln!(file)?;
        }

        writeln!(file, "Recent Anomalies")?;
        writeln!(file, "----------------")?;
        for anomaly in self.anomalies.iter().rev().take(20) {
            writeln!(
                file,
                "[{}] [{}] {}: {}",
                anomaly.detected_at.format("%Y-%m-%d %H:%M:%S"),
                anomaly.severity,
                match &anomaly.anomaly_type {
                    crate::models::AnomalyType::ErrorSpike => "ERROR_SPIKE",
                    crate::models::AnomalyType::RepeatedEvent => "REPEATED",
                    crate::models::AnomalyType::VolumeSpike => "VOLUME",
                    crate::models::AnomalyType::RuleViolation => "RULE",
                },
                anomaly.description
            )?;
        }

        Ok(())
    }
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
