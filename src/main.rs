//! AIRX 主程序入口（bin target）
#![allow(dead_code)]

mod api;
mod auth;
mod config;
mod db;
mod i18n;
mod login_limiter;
mod models;
mod utils;
mod web;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use api::admin::{self, AdminState};
use config::ConfigManager;
use db::Db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // 加载配置
    let config_manager = Arc::new(ConfigManager::new(None).await);
    let config = config_manager.get().await;
    // 同步函数（如 admin::do_login）依赖全局快照
    config::set_snapshot(Arc::new(config.clone()));

    // 初始化数据库（rusqlite，读现有 GORM 库）
    let db_path = db::db_path(&config);
    let db = Arc::new(Db::open(&db_path)?);
    db.init_schema()?;

    let login_limiter = Arc::new(crate::login_limiter::LoginLimiter::new(
        crate::login_limiter::SecurityPolicy {
            captcha_threshold: config.app.captcha_threshold,
            ban_threshold: config.app.ban_threshold,
            attempts_window: std::time::Duration::from_secs(5 * 60),
            ban_duration: std::time::Duration::from_secs(30 * 60),
        },
    ));
    let state = AdminState {
        config_manager: config_manager.clone(),
        db: db.clone(),
        login_limiter,
    };

    let app = build_router(state, &config);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Starting airx server at {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    Ok(())
}

fn build_router(state: AdminState, config: &config::AppConfig) -> Router {
    // 客户端 API（/api/*）
    let client_routes = api::client::routes();
    // 管理面 API（/api/admin/*）
    let admin_routes = admin::routes(state.clone());

    Router::new()
        .merge(client_routes)
        .merge(admin_routes)
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .fallback_service(web::serve_static_files())
        .layer(build_cors_layer(config))
        .layer(CompressionLayer::new())
        .with_state(state)
}

fn build_cors_layer(_config: &config::AppConfig) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("api-token"),
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT_LANGUAGE,
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
}
