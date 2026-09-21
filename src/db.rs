//! 数据库访问层：rusqlite(bundled) 直读现有 GORM 建库的 SQLite
//!
//! 表结构权威来源：src/db_schema.sql（从旧库 sqlite_master 导出）。
//! 启动时执行该 SQL（CREATE TABLE IF NOT EXISTS 幂等），全新安装与旧库复用一致。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::config::AppConfig;

/// 数据库连接（Mutex 包裹；airx 为低频管理后端，单连接足够）
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // WAL 提升并发读写稳定性
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// 执行 db_schema.sql 建表（幂等）
    pub fn init_schema(&self) -> anyhow::Result<()> {
        let sql = include_str!("db_schema.sql");
        let conn = self.conn.lock().unwrap();
        for stmt in split_sql(sql) {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            conn.execute_batch(stmt)?;
        }
        // 旧库补列（GORM 原表无 tfa_secret；AIRX TOTP 增强）。幂等。
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN tfa_secret text NOT NULL DEFAULT ''",
            [],
        );
        Ok(())
    }

    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }
}

/// 计算数据库文件路径
pub fn db_path(config: &AppConfig) -> PathBuf {
    let data_dir = crate::config::expand_path(&config.server.data_dir);
    data_dir.join("rustdeskapi.db")
}

/// 简单拆分 SQL 语句（按分号，忽略注释行）。schema 里每表一句，足够。
fn split_sql(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--") || trimmed.is_empty() {
            if !current.trim().is_empty() {
                out.push(current.trim().to_string());
                current.clear();
            }
            continue;
        }
        current.push_str(line);
        current.push('\n');
        if trimmed.ends_with(';') {
            out.push(current.trim().to_string());
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

/// 当前 Unix 秒
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// AutoTime 序列化格式："2006-01-02 15:04:05"（对齐 Go custom_types.AutoTime）
/// 数据库里存的是 "2026-09-18 09:08:24.570323984+00:00" 长格式，这里截取前 19 位。
pub fn format_autotime(s: &str) -> String {
    if s.len() >= 19 {
        s[0..19].to_string()
    } else {
        s.to_string()
    }
}

/// AutoJson Scan：空串/解析失败 → "[]"；否则原样返回（对齐 Go custom_types.AutoJson）
pub fn normalize_autojson(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "[]".to_string();
    }
    match serde_json::from_str::<serde_json::Value>(t) {
        Ok(_) => t.to_string(),
        Err(_) => "[]".to_string(),
    }
}
