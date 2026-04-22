mod handlers;
mod models;

use axum::{
    routing::{get, post},
    Router,
};
use handlers::AppStateInner;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let (tx, _rx) = broadcast::channel(100);
    
    let state = Arc::new(AppStateInner {
        logs: dashmap::DashMap::new(),
        next_id: std::sync::atomic::AtomicU64::new(0),
        tx,
    });
    
    // Создаем сервис для раздачи статических файлов из папки "static"
    let serve_dir = ServeDir::new("static");

    let app = Router::new()
        .route("/", get(handlers::index_handler))
        .route("/api/logs", get(handlers::logs_handler))
        .route("/api/logs", post(handlers::add_log_handler))
        .route("/api/stats", get(handlers::stats_handler))
        .route("/ws", get(handlers::ws_handler))
        // Добавляем фоллбэк для статики: если путь не найден в API, ищем в папке static
        .nest_service("/", serve_dir)
        .with_state(state);
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}