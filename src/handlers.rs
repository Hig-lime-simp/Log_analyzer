use axum::{
    extract::{State, WebSocketUpgrade, ws::WebSocket},
    response::{Html, IntoResponse},
    Json,
};
use dashmap::DashMap;
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::models::{LogEntry, LogLevel};

pub type AppState = Arc<AppStateInner>;

pub struct AppStateInner {
    pub logs: DashMap<u64, LogEntry>,
    pub next_id: std::sync::atomic::AtomicU64,
    pub tx: broadcast::Sender<LogEntry>,
}

pub async fn index_handler() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

pub async fn add_log_handler(
    State(state): State<AppState>,
    Json(content): Json<String>,
) -> Json<LogEntry> {
    let id = state.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let entry = LogEntry::new(id, content);
    
    state.logs.insert(id, entry.clone());
    let _ = state.tx.send(entry.clone());
    
    Json(entry)
}

pub async fn logs_handler(State(state): State<AppState>) -> Json<Vec<LogEntry>> {
    let mut logs: Vec<_> = state.logs.iter().map(|entry| entry.value().clone()).collect();
    logs.sort_by_key(|log| log.timestamp);
    Json(logs)
}

pub async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let total = state.logs.len();
    let errors = state.logs.iter().filter(|e| e.value().level == LogLevel::Error).count();
    let warnings = state.logs.iter().filter(|e| e.value().level == LogLevel::Warning).count();
    
    Json(serde_json::json!({
        "total": total,
        "errors": errors,
        "warnings": warnings,
        "info": total - errors - warnings,
    }))
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket: WebSocket| async move {
        let mut rx = state.tx.subscribe();
        
        let (mut sender, _) = socket.split();
        
        while let Ok(entry) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = sender.send(axum::extract::ws::Message::Text(json)).await;
            }
        }
    })
}