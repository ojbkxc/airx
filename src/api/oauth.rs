//! OAuth/OIDC + webauth（对齐 Go http/controller/api/ouath.go + service/oauth.go）
//!
//! state 存内存 OauthCache（DashMap），PKCE verifier/nonce 一并缓存。
//! P3 完整实现；先提供 provider 列表查询与基础端点骨架。

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use crate::api::admin::AdminState;

/// OAuth 缓存条目（对齐 Go service.OauthCacheItem）
#[derive(Clone, Debug)]
pub struct OauthCacheItem {
    pub action: String, // login / bind
    pub op: String,
    pub id: String,
    pub device_type: String,
    pub device_os: String,
    pub uuid: String,
    pub verifier: String,
    pub nonce: String,
}

/// 全局 OAuth 缓存（进程内）
static OAUTH_CACHE: Mutex<Option<HashMap<String, (OauthCacheItem, i64)>>> = Mutex::new(None);

fn cache() -> std::sync::MutexGuard<'static, Option<HashMap<String, (OauthCacheItem, i64)>>> {
    OAUTH_CACHE.lock().unwrap()
}

pub fn oauth_cache_get(state: &str) -> Option<OauthCacheItem> {
    let mut g = cache();
    if let Some(map) = g.as_mut() {
        if let Some((item, exp)) = map.get(state) {
            if *exp > crate::db::now_unix() {
                return Some(item.clone());
            }
        }
    }
    None
}

pub fn oauth_cache_set(state: &str, item: OauthCacheItem, ttl_secs: i64) {
    let mut g = cache();
    let map = g.get_or_insert_with(HashMap::new);
    map.insert(state.to_string(), (item, crate::db::now_unix() + ttl_secs));
}

/// 查询启用的 OAuth provider op 列表（对齐 Go OauthService.GetOauthProviders）
pub fn oauth_provider_ops(state: &AdminState) -> Vec<String> {
    let conn = state.db.conn();
    let mut stmt = match conn.prepare("SELECT op FROM oauths") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let ops: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    ops
}

/// 校验 captcha（登录限流：P3）
pub fn verify_captcha(_id: &str, _code: &str) -> bool {
    true
}

// ─────────────────────────── 管理面 OIDC ───────────────────────────

/// POST /api/admin/oidc/auth
pub async fn handle_admin_oidc_auth(
    State(_state): State<AdminState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if op.is_empty() {
        return Err(crate::api::common::error("ParamsError"));
    }
    let state_code = crate::utils::generate_token(&format!("oidc{}", op));
    let item = OauthCacheItem {
        action: "login".to_string(),
        op: op.clone(),
        id: body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_type: "webadmin".to_string(),
        device_os: body
            .get("deviceInfo")
            .and_then(|d| d.get("os"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uuid: body
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        verifier: String::new(),
        nonce: String::new(),
    };
    oauth_cache_set(&state_code, item, 5 * 60);
    // P3：真实 OIDC 需构造授权 URL。这里返回占位 URL。
    let url = format!("oidc://authorize?op={}", op);
    Ok(crate::api::common::success(
        json!({ "code": state_code, "url": url }),
    ))
}

/// GET /api/admin/oidc/auth-query
pub async fn handle_admin_oidc_auth_query(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    // P3：按 state 查询授权结果。未授权返回 error。
    crate::api::common::fail(101, "NoAuthedOidc")
}

// ─────────────────────────── 管理面 OAuth 绑定 ───────────────────────────

/// POST /api/admin/oauth/confirm
pub async fn handle_oauth_confirm(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::success(Value::Null)
}

/// POST /api/admin/oauth/bind
pub async fn handle_oauth_bind(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::fail(101, "ParamsError")
}

/// POST /api/admin/oauth/bindConfirm
pub async fn handle_oauth_bind_confirm(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::fail(101, "ParamsError")
}

/// POST /api/admin/oauth/unbind
pub async fn handle_oauth_unbind(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::success(Value::Null)
}

/// GET /api/admin/oauth/info
pub async fn handle_oauth_info(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::success(Value::Null)
}
// ─────────────────────────── 客户端 OAuth/OIDC（占位，P3 完整实现） ───────────────────────────

/// POST /api/oidc/auth
pub async fn handle_oidc_auth(
    State(_state): State<AdminState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if op.is_empty() {
        return Err(crate::api::common::error("ParamsError"));
    }
    let state_code = crate::utils::generate_token(&format!("oidc{}", op));
    let item = OauthCacheItem {
        action: "login".to_string(),
        op: op.clone(),
        id: body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_type: "app".to_string(),
        device_os: body
            .get("deviceInfo")
            .and_then(|d| d.get("os"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uuid: body
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        verifier: String::new(),
        nonce: String::new(),
    };
    oauth_cache_set(&state_code, item, 5 * 60);
    let url = format!("oidc://authorize?op={}", op);
    Ok(crate::api::common::success(
        json!({ "code": state_code, "url": url }),
    ))
}

/// GET /api/oidc/auth-query
pub async fn handle_oidc_auth_query(
    State(_state): State<AdminState>,
    _headers: HeaderMap,
) -> Json<Value> {
    crate::api::common::fail(101, "NoAuthedOidc")
}

/// GET /api/oauth/callback | /oauth/login | /oidc/callback | /oidc/login
pub async fn handle_oauth_callback() -> &'static str {
    "NotImplemented"
}

/// GET /api/oauth/msg | /oidc/msg
pub async fn handle_oauth_msg() -> &'static str {
    "NotImplemented"
}
