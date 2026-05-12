use axum::{ //импорт компанентов
    extract::{State, WebSocketUpgrade, ws::WebSocket}, //получение доступа к общему состоянию приложения
    response::{Html, IntoResponse}, //типы ответов
    Json, //json и в Африке json
};
use dashmap::DashMap; // потокобезопасная карта
use futures_util::{sink::SinkExt, stream::StreamExt}; //работа с потоками
use std::sync::Arc; // указкать для работы между потоками
use tokio::sync::broadcast; // отправка соо через pub\sub

use crate::models::{LogEntry, LogLevel}; // создаем обьекты 

pub type AppState = Arc<AppStateInner>; // сохранение состояние приложения 

pub struct AppStateInner {
    pub logs: DashMap<u64, LogEntry>,
    pub next_id: std::sync::atomic::AtomicU64,
    pub tx: broadcast::Sender<LogEntry>,
}

pub async fn index_handler() -> impl IntoResponse {
    Html(include_str!("../static/index.html")) // обработка html файла и превращение его в запрос http
}

pub async fn add_log_handler( // Создание лога, паср его в json 
    State(state): State<AppState>,
    Json(content): Json<String>,
) -> Json<LogEntry> {
    let id = state.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let entry = LogEntry::new(id, content);
    
    state.logs.insert(id, entry.clone());
    let _ = state.tx.send(entry.clone());
    
    Json(entry)
}

pub async fn logs_handler(State(state): State<AppState>) -> Json<Vec<LogEntry>> { //GET 
    let mut logs: Vec<_> = state.logs.iter().map(|entry| entry.value().clone()).collect();
    logs.sort_by_key(|log| log.timestamp);
    Json(logs)
}

pub async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> { // Запрос на получение кол-ва всех типов логов
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

pub async fn ws_handler( // Соединение сервера, бесконечнаая загрузка логов
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket: WebSocket| async move {
        let mut rx = state.tx.subscribe(); //Обьект-подписчик, способный только на read
        
        let (mut sender, _) = socket.split();
        
        while let Ok(entry) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = sender.send(axum::extract::ws::Message::Text(json)).await;
            }
        }
    })
}