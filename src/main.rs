mod handlers;
mod models;

use axum::{
    routing::{get, post}, // GET and POST запросы
    Router,
};
use handlers::AppStateInner;
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    let (tx, _rx) = broadcast::channel(100); // на сервере храниться будет только 100 соо
    
    let state = Arc::new(AppStateInner { //загрзка состояние 
        logs: dashmap::DashMap::new(),
        next_id: std::sync::atomic::AtomicU64::new(0),
        tx,
    });

    let app = Router::new()
        .route("/api/logs", get(handlers::logs_handler)) // Получение списка логов
        .route("/api/logs", post(handlers::add_log_handler))// Добавление лога
        .route("/api/stats", get(handlers::stats_handler))// Получение стастистики
        .route("/ws", get(handlers::ws_handler))// Соедине Websocket
        .route("/", get(handlers::index_handler))//Загурзка html
        .with_state(state);// Доступ
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap(); // Создание сервера
    axum::serve(listener, app).await.unwrap(); //Запуск
}