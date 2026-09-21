//! AIRX — RustDesk 自建服务器管理后端（Rust 重写版）
//!
//! 与 AIGX 为姊妹项目：单仓库（后端 + 前端 static）、axum 0.7、rusqlite(bundled) SQLite。
//! API 契约逐字节对齐 lejianwen/rustdesk-api（Go 版），保证 RustDesk 客户端与 Vue 前端无缝工作。

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod models;
pub mod utils;
pub mod web;
