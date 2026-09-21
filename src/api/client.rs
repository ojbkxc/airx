//! 客户端 API（RustDesk Client / Web Client，对齐 Go http/controller/api/*）
//!
//! 响应格式与 Go 完全一致：
//! - response.Success → {"code":0,"message":"success","data":...}
//! - response.Error    → HTTP 400 {"error": "..."}
//! - DataResponse      → {"total":n,"data":[...]}
//! - 文本端点（sysinfo/audit/tag 操作）→ c.String

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::admin::AdminState;
use crate::api::common;
use crate::auth;
use crate::models::User;

/// 版本号（resources/version 内容；空实现与 Go 一致——文件缺省时返回空）
pub fn app_version() -> String {
    std::fs::read_to_string("resources/version").unwrap_or_default()
}

/// 客户端鉴权失败 → 401 {"error":"Unauthorized"}
fn unauthorized() -> Response {
    let (status, body) = common::unauthorized();
    (status, body).into_response()
}

#[allow(clippy::result_large_err)]
async fn auth(state: &AdminState, headers: &HeaderMap) -> Result<User, Response> {
    let config = state.config_manager.get().await;
    auth::rust_auth(&state.db, headers, config.app.token_expire_secs).map_err(|_| unauthorized())
}

/// 路由注册（对齐 Go http/router/api.go）
pub fn routes() -> Router<AdminState> {
    let mut r = Router::new()
        // index
        .route("/api/", get(handle_index))
        .route("/api/version", get(handle_version))
        .route("/api/heartbeat", post(handle_heartbeat))
        // login
        .route("/api/login-options", get(handle_login_options))
        .route("/api/login", post(handle_login))
        .route("/api/logout", post(handle_logout))
        // oauth / oidc（占位实现在 oauth.rs）
        .route("/api/oidc/auth", post(crate::api::oauth::handle_oidc_auth))
        .route(
            "/api/oidc/auth-query",
            get(crate::api::oauth::handle_oidc_auth_query),
        )
        .route(
            "/api/oauth/callback",
            get(crate::api::oauth::handle_oauth_callback),
        )
        .route(
            "/api/oauth/login",
            get(crate::api::oauth::handle_oauth_callback),
        )
        .route("/api/oauth/msg", get(crate::api::oauth::handle_oauth_msg))
        .route(
            "/api/oidc/callback",
            get(crate::api::oauth::handle_oauth_callback),
        )
        .route(
            "/api/oidc/login",
            get(crate::api::oauth::handle_oauth_callback),
        )
        .route("/api/oidc/msg", get(crate::api::oauth::handle_oauth_msg))
        // peer
        .route("/api/sysinfo", post(handle_sysinfo))
        .route("/api/sysinfo_ver", post(handle_sysinfo_ver))
        // audit
        .route("/api/audit/conn", post(handle_audit_conn))
        .route("/api/audit/file", post(handle_audit_file))
        // 需登录
        .route("/api/user/info", get(handle_user_info))
        .route("/api/currentUser", post(handle_user_info))
        .route("/api/users", get(handle_users))
        .route("/api/peers", get(handle_peers))
        .route("/api/device-group/accessible", get(handle_device_group))
        // ab（旧版）
        .route("/api/ab", get(handle_ab).post(handle_up_ab))
        // ab personal 系列
        .route("/api/ab/personal", post(handle_ab_personal))
        .route("/api/ab/settings", post(handle_ab_settings))
        .route("/api/ab/shared/profiles", post(handle_ab_shared_profiles))
        .route("/api/ab/peers", post(handle_ab_peers))
        .route("/api/ab/tags/:guid", post(handle_ab_tags))
        .route("/api/ab/peer/add/:guid", post(handle_ab_peer_add))
        .route(
            "/api/ab/peer/:guid",
            axum::routing::delete(handle_ab_peer_del),
        )
        .route(
            "/api/ab/peer/update/:guid",
            axum::routing::put(handle_ab_peer_update),
        )
        .route("/api/ab/tag/add/:guid", post(handle_ab_tag_add))
        .route(
            "/api/ab/tag/rename/:guid",
            axum::routing::put(handle_ab_tag_rename),
        )
        .route(
            "/api/ab/tag/update/:guid",
            axum::routing::put(handle_ab_tag_update),
        )
        .route(
            "/api/ab/tag/:guid",
            axum::routing::delete(handle_ab_tag_del),
        )
        // web client
        .route("/api/shared-peer", post(handle_shared_peer))
        .route("/api/server-config", post(handle_server_config))
        .route("/api/server-config-v2", post(handle_server_config_v2));
    let _ = &mut r;
    r
}

// ══════════════════════════════════════════════════════════════════
// index
// ══════════════════════════════════════════════════════════════════

/// GET /api/ → {"code":0,"message":"success","data":"Hello Gwen"}
async fn handle_index() -> Json<Value> {
    common::success(json!("Hello Gwen"))
}

/// GET /api/version
async fn handle_version() -> Json<Value> {
    common::success(json!(app_version()))
}

/// POST /api/heartbeat —— 30s 节流更新 last_online_time/last_online_ip
async fn handle_heartbeat(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let uuid = b.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() || uuid.is_empty() {
        return Json(json!({}));
    }
    let conn = state.db.conn();
    let (row_id, last): (i64, i64) = match conn.query_row(
        "SELECT row_id, last_online_time FROM peers WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ) {
        Ok(x) => x,
        Err(_) => {
            drop(conn);
            return Json(json!({}));
        }
    };
    if row_id == 0 {
        drop(conn);
        return Json(json!({}));
    }
    if crate::db::now_unix() - last >= 30 {
        let ip = crate::utils::client_ip(&headers, "");
        let _ = conn.execute(
            "UPDATE peers SET last_online_time = ?1, last_online_ip = ?2, updated_at = ?3 WHERE row_id = ?4",
            rusqlite::params![
                crate::db::now_unix(),
                ip,
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f+00:00").to_string(),
                row_id
            ],
        );
    }
    drop(conn);
    Json(json!({}))
}

// ══════════════════════════════════════════════════════════════════
// login
// ══════════════════════════════════════════════════════════════════

/// POST /api/login → LoginRes{type,access_token,user}
async fn handle_login(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Response {
    let config = state.config_manager.get().await;
    if config.app.disable_pwd_login {
        return error_text("PwdLoginDisabled");
    }
    let username = b.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = b.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if username.is_empty() || password.is_empty() {
        return error_text("ParamsError");
    }
    let user = match crate::api::admin::user_by_username(&state.db, username) {
        Some(u) if u.id > 0 => u,
        _ => return error_text("UsernameOrPasswordError"),
    };
    let (ok, new_hash) = crate::utils::verify_password(&user.password, password);
    if !ok {
        return error_text("UsernameOrPasswordError");
    }
    if let Some(new_hash) = new_hash {
        let conn = state.db.conn();
        let _ = conn.execute(
            "UPDATE users SET password = ?1 WHERE id = ?2",
            rusqlite::params![new_hash, user.id],
        );
    }
    if !user.is_enabled() {
        return error_text("UserDisabled");
    }

    let uuid = b
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let device_id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // referer 存在 → webclient
    let client = if headers.contains_key("referer") {
        "webclient"
    } else {
        "app"
    };
    let platform = b
        .get("device_info")
        .and_then(|d| d.get("os"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ip = crate::utils::client_ip(&headers, "");
    let token = crate::api::admin::do_login(
        &state,
        &user,
        &crate::models::LoginLog {
            client: client.to_string(),
            uuid,
            ip,
            type_: "account".to_string(),
            platform,
            device_id,
            ..Default::default()
        },
    );
    Json(json!({
        "type": "access_token",
        "access_token": token,
        "user": user_payload(&user),
    }))
    .into_response()
}

/// GET /api/login-options → ["common-oidc/[{name:op},...]", "oidc/op", ...]
async fn handle_login_options(State(state): State<AdminState>) -> Json<Value> {
    let config = state.config_manager.get().await;
    let mut ops = crate::api::oauth::oauth_provider_ops(&state);
    if config.app.web_sso {
        ops.push("webauth".to_string());
    }
    let oidc_items: Vec<Value> = ops.iter().map(|v| json!({ "name": v })).collect();
    let common_str = serde_json::to_string(&oidc_items).unwrap_or_else(|_| "[]".into());
    let mut res = vec![format!("common-oidc/{}", common_str)];
    for v in &ops {
        res.push(format!("oidc/{}", v));
    }
    Json(json!(res))
}

/// POST /api/logout → null（200）
async fn handle_logout(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let config = state.config_manager.get().await;
    if let Ok(user) = auth::rust_auth(&state.db, &headers, config.app.token_expire_secs) {
        if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            let token = auth.strip_prefix("Bearer ").unwrap_or("");
            let conn = state.db.conn();
            let _ = conn.execute(
                "DELETE FROM user_tokens WHERE token = ?1 AND user_id = ?2",
                rusqlite::params![token, user.id],
            );
            drop(conn);
        }
    }
    Json(Value::Null).into_response()
}

fn error_text(msg: &str) -> Response {
    let (status, body) = common::error(msg);
    (status, body).into_response()
}

/// UserPayload（对齐 Go apiResp.UserPayload）
fn user_payload(u: &User) -> Value {
    json!({
        "name": u.username,
        "email": u.email,
        "note": u.remark,
        "is_admin": u.is_admin,
        "status": u.status,
        "info": {},
    })
}

// ══════════════════════════════════════════════════════════════════
// peer：sysinfo
// ══════════════════════════════════════════════════════════════════

/// POST /api/sysinfo → 文本 "SYSINFO_UPDATED"
async fn handle_sysinfo(State(state): State<AdminState>, Json(b): Json<Value>) -> Response {
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return error_text("ParamsError");
    }
    let uuid = b
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let conn = state.db.conn();
    let existing: Option<(i64, i64)> = conn
        .query_row(
            "SELECT row_id, user_id FROM peers WHERE id = ?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    match existing {
        None => {
            // 创建；user_id 取 login_log 中 uuid+device_id 最近记录
            let uid: i64 = if uuid.is_empty() {
                0
            } else {
                conn.query_row(
                    "SELECT user_id FROM login_logs WHERE uuid = ?1 AND device_id = ?2 ORDER BY id DESC LIMIT 1",
                    [&uuid, &id],
                    |r| r.get(0),
                )
                .unwrap_or(0)
            };
            let res = conn.execute(
                "INSERT INTO peers (id, cpu, hostname, memory, os, username, uuid, version, user_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                rusqlite::params![
                    id,
                    b.get("cpu").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("memory").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("os").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                    uuid,
                    b.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                    uid,
                    now,
                ],
            );
            drop(conn);
            if res.is_err() {
                return error_text("OperationFailed");
            }
        }
        Some((row_id, mut uid)) => {
            if uid == 0 && !uuid.is_empty() {
                uid = conn
                    .query_row(
                        "SELECT user_id FROM login_logs WHERE uuid = ?1 AND device_id = ?2 ORDER BY id DESC LIMIT 1",
                        [&uuid, &id],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
            }
            let _ = conn.execute(
                "UPDATE peers SET cpu=?1, hostname=?2, memory=?3, os=?4, username=?5, uuid=?6, version=?7, user_id=?8, updated_at=?9 WHERE row_id=?10",
                rusqlite::params![
                    b.get("cpu").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("memory").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("os").and_then(|v| v.as_str()).unwrap_or(""),
                    b.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                    uuid,
                    b.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                    uid,
                    now,
                    row_id,
                ],
            );
            drop(conn);
        }
    }
    plain_text("SYSINFO_UPDATED")
}

/// POST /api/sysinfo_ver → "版本\n启动时间"
async fn handle_sysinfo_ver() -> Response {
    plain_text(&format!("{}\n{}", app_version(), start_time_str()))
}

fn start_time_str() -> String {
    START_TIME_ONCE
        .get_or_init(|| chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string())
        .clone()
}

use std::sync::OnceLock;
static START_TIME_ONCE: OnceLock<String> = OnceLock::new();

fn plain_text(s: &str) -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        s.to_string(),
    )
        .into_response()
}

// ══════════════════════════════════════════════════════════════════
// audit
// ══════════════════════════════════════════════════════════════════

/// POST /api/audit/conn —— action=new 插入 / close 更新 close_time / 空串 更新部分字段
async fn handle_audit_conn(State(state): State<AdminState>, Json(b): Json<Value>) -> Json<Value> {
    let action = b
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let conn_id = b.get("conn_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let peer = b
        .get("peer")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let from_peer = peer
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let from_name = peer
        .get(1)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let ip = b
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // session_id float 去尾零（对齐 Go strconv.FormatFloat -1）
    let session_id = b
        .get("session_id")
        .and_then(|v| v.as_f64())
        .map(|f| {
            let s = format!("{:.6}", f);
            let s = s.trim_end_matches('0').trim_end_matches('.');
            s.to_string()
        })
        .unwrap_or_default();
    let type_ = b.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
    let uuid = b
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();

    let conn = state.db.conn();
    if action == "new" {
        let _ = conn.execute(
            "INSERT INTO audit_conns (action, conn_id, peer_id, from_peer, from_name, ip, session_id, type, uuid, close_time, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?10)",
            rusqlite::params![action, conn_id, id, from_peer, from_name, ip, session_id, type_, uuid, now],
        );
    } else if action == "close" {
        let _ = conn.execute(
            "UPDATE audit_conns SET close_time = ?1, updated_at = ?2 WHERE peer_id = ?3 AND conn_id = ?4",
            rusqlite::params![crate::db::now_unix(), now, id, conn_id],
        );
    } else {
        // action == ""
        let _ = conn.execute(
            "UPDATE audit_conns SET from_peer = ?1, from_name = ?2, session_id = ?3, type = ?4, updated_at = ?5 WHERE peer_id = ?6 AND conn_id = ?7",
            rusqlite::params![from_peer, from_name, session_id, type_, now, id, conn_id],
        );
    }
    drop(conn);
    common::success(json!(""))
}

/// POST /api/audit/file
async fn handle_audit_file(State(state): State<AdminState>, Json(b): Json<Value>) -> Json<Value> {
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let info = b
        .get("info")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let is_file = b.get("is_file").and_then(|v| v.as_bool()).unwrap_or(false);
    let path = b
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let peer_id = b
        .get("peer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let type_ = b.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
    let uuid = b
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // info JSON → {ip, name, num}
    let fi: Value = serde_json::from_str(&info).unwrap_or(json!({}));
    let f_ip = fi
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let f_name = fi
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let f_num = fi.get("num").and_then(|v| v.as_i64()).unwrap_or(0);
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let conn = state.db.conn();
    let _ = conn.execute(
        "INSERT INTO audit_files (from_peer, info, is_file, path, peer_id, type, uuid, ip, num, from_name, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11)",
        rusqlite::params![peer_id, info, is_file as i64, path, id, type_, uuid, f_ip, f_num, f_name, now],
    );
    drop(conn);
    common::success(json!(""))
}

// ══════════════════════════════════════════════════════════════════
// user / group（需登录）
// ══════════════════════════════════════════════════════════════════

/// GET/POST /api/user/info|currentUser → UserPayload
async fn handle_user_info(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    Json(user_payload(&user)).into_response()
}

#[derive(Debug, Deserialize, Default)]
struct PageOnly {
    #[serde(default)]
    current: i64,
    #[serde(default)]
    #[serde(alias = "pageSize")]
    page_size: i64,
}

fn page_of(q: &PageOnly) -> (i64, i64) {
    let page = if q.current <= 0 { 1 } else { q.current };
    let size = if q.page_size <= 0 { 10 } else { q.page_size };
    (page, size)
}

/// GET /api/users → DataResponse{total,data:[UserPayload]}
async fn handle_users(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageOnly>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let conn = state.db.conn();
    // 组类型：type=2 共享组
    let group_type: i64 = conn
        .query_row(
            "SELECT type FROM groups WHERE id = ?1",
            [user.group_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let (page, size) = page_of(&q);
    let offset = (page - 1) * size;
    let (total, users): (i64, Vec<Value>) = if !user.is_admin && group_type != 2 {
        (1, vec![user_payload(&user)])
    } else {
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE group_id = ?1",
                [user.group_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let rows: Vec<Value> = conn
            .prepare("SELECT id, username, email, remark, is_admin, status FROM users WHERE group_id = ?1 ORDER BY id LIMIT ?2 OFFSET ?3")
            .ok()
            .and_then(|mut stmt| {
                stmt.query_map([user.group_id, size, offset], |r| {
                    Ok(json!({
                        "name": r.get::<_, String>(1)?,
                        "email": r.get::<_, String>(2)?,
                        "note": r.get::<_, String>(3)?,
                        "is_admin": r.get::<_, i64>(4)? != 0,
                        "status": r.get::<_, i64>(5)?,
                        "info": {},
                    }))
                })
                .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
            })
            .unwrap_or_default();
        (total, rows)
    };
    drop(conn);
    Json(json!({ "total": total, "data": users })).into_response()
}

/// GET /api/peers → DataResponse{total,data:[GroupPeerPayload]}
async fn handle_peers(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageOnly>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (page, size) = page_of(&q);
    let offset = (page - 1) * size;
    let conn = state.db.conn();
    let group_type: i64 = conn
        .query_row(
            "SELECT type FROM groups WHERE id = ?1",
            [user.group_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    // 可见用户集合
    let visible: Vec<(i64, String)> = if !user.is_admin && group_type != 2 {
        vec![(user.id, user.username.clone())]
    } else {
        conn.prepare("SELECT id, username FROM users WHERE group_id = ?1 ORDER BY id")
            .ok()
            .and_then(|mut stmt| {
                stmt.query_map([user.group_id], |r| Ok((r.get(0)?, r.get(1)?)))
                    .ok()
                    .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
            })
            .unwrap_or_default()
    };
    let names: std::collections::HashMap<i64, String> = visible.iter().cloned().collect();
    let uids: Vec<i64> = visible.iter().map(|x| x.0).collect();
    // device_group 名映射
    let dgroups: std::collections::HashMap<i64, String> = conn
        .prepare("SELECT id, name FROM device_groups")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default()
        .into_iter()
        .collect();
    let total: i64 = if uids.is_empty() {
        0
    } else {
        let placeholders = uids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let params: Vec<&dyn rusqlite::ToSql> =
            uids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM peers WHERE user_id IN ({})",
                placeholders
            ),
            params.as_slice(),
            |r| r.get(0),
        )
        .unwrap_or(0)
    };
    let mut data: Vec<Value> = Vec::new();
    if !uids.is_empty() {
        let placeholders = uids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut params: Vec<&dyn rusqlite::ToSql> =
            uids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
        params.push(&size);
        params.push(&offset);
        data = conn
            .prepare(&format!(
                "SELECT id, hostname, os, username, user_id, group_id FROM peers WHERE user_id IN ({}) ORDER BY row_id LIMIT ?{} OFFSET ?{}",
                placeholders, params.len() - 1, params.len()
            ))
            .ok()
            .and_then(|mut stmt| {
                stmt.query_map(params.as_slice(), |r| {
                    let uid: i64 = r.get(4)?;
                    let gid: i64 = r.get(5)?;
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "info": {
                            "device_name": r.get::<_, String>(1)?,
                            "os": r.get::<_, String>(2)?,
                            "username": r.get::<_, String>(3)?,
                        },
                        "status": 0,
                        "user": names.get(&uid).cloned().unwrap_or_default(),
                        "user_name": names.get(&uid).cloned().unwrap_or_default(),
                        "note": "",
                        "device_group_name": dgroups.get(&gid).cloned().unwrap_or_default(),
                    }))
                })
                .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
            })
            .unwrap_or_default();
    }
    drop(conn);
    Json(json!({ "total": total, "data": data })).into_response()
}

/// GET /api/device-group/accessible —— 仅 admin
async fn handle_device_group(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    if !user.is_admin() {
        return error_text("Permission denied");
    }
    let conn = state.db.conn();
    let data: Vec<Value> = conn
        .prepare("SELECT id, name, created_at, updated_at FROM device_groups ORDER BY id LIMIT 999 OFFSET 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "created_at": crate::db::format_autotime(&r.get::<_, String>(2)?),
                    "updated_at": crate::db::format_autotime(&r.get::<_, String>(3)?),
                }))
            })
            .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    drop(conn);
    Json(json!({ "total": 0, "data": data })).into_response()
}

// ══════════════════════════════════════════════════════════════════
// ab（旧版 GET / POST）
// ══════════════════════════════════════════════════════════════════

/// GET /api/ab → {"data":"{\"peers\":[...],\"tags\":[...],\"tag_colors\":\"...\"}"}
async fn handle_ab(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let conn = state.db.conn();
    // address_books（user_id=自己，collection_id=0）
    let peers: Vec<Value> = conn
        .prepare("SELECT * FROM address_books WHERE user_id = ?1 AND collection_id = 0 LIMIT 1000 OFFSET 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], crate::api::crud::ab_row_to_json)
                .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    // tags
    let tag_rows: Vec<(String, i64)> = conn
        .prepare("SELECT name, color FROM tags WHERE user_id = ?1 AND collection_id = 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], |r| Ok((r.get(0)?, r.get(1)?)))
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    let tags: Vec<String> = tag_rows.iter().map(|t| t.0.clone()).collect();
    let tag_colors: Value = tag_rows
        .iter()
        .map(|t| (t.0.clone(), json!(t.1)))
        .collect::<serde_json::Map<String, Value>>()
        .into();
    let inner = json!({
        "peers": peers,
        "tags": tags,
        "tag_colors": serde_json::to_string(&tag_colors).unwrap_or_else(|_| "{}".into()),
    });
    Json(json!({ "data": serde_json::to_string(&inner).unwrap_or_default() })).into_response()
}

/// POST /api/ab —— 全量同步 address_books + tags
async fn handle_up_ab(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let data_str = b.get("data").and_then(|v| v.as_str()).unwrap_or("");
    let abd: Value = match serde_json::from_str(data_str) {
        Ok(v) => v,
        Err(_) => return error_text("ParamsError"),
    };
    let peers = abd
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let tag_colors_str = abd
        .get("tag_colors")
        .and_then(|v| v.as_str())
        .unwrap_or("{}");
    let tc: std::collections::HashMap<String, i64> =
        serde_json::from_str(tag_colors_str).unwrap_or_default();

    let conn = state.db.conn();
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let _ = conn.execute_batch("BEGIN");
    // 库中已有
    let db_ids: Vec<(i64, String)> = conn
        .prepare("SELECT row_id, id FROM address_books WHERE user_id = ?1")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], |r| Ok((r.get(0)?, r.get(1)?)))
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    let db_map: std::collections::HashMap<String, i64> =
        db_ids.iter().map(|(rid, id)| (id.clone(), *rid)).collect();
    // 上传的
    let mut up_ids: std::collections::HashMap<String, ()> = std::collections::HashMap::new();
    for ab in &peers {
        let id = ab.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            continue;
        }
        up_ids.insert(id.to_string(), ());
        let tags = match ab.get("tags") {
            Some(Value::Array(_)) => {
                serde_json::to_string(ab.get("tags").unwrap()).unwrap_or_else(|_| "[]".into())
            }
            _ => "null".to_string(),
        };
        match db_map.get(id) {
            None => {
                // 补 platform/username/hostname
                let (mut platform, mut username, mut hostname) = (
                    ab.get("platform")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    ab.get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    ab.get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                );
                if platform.is_empty() || username.is_empty() || hostname.is_empty() {
                    if let Ok((os, un, hn)) = conn.query_row(
                        "SELECT os, username, hostname FROM peers WHERE id = ?1",
                        [id],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                            ))
                        },
                    ) {
                        platform = crate::api::crud::platform_from_os_str(&os);
                        username = un;
                        hostname = hn;
                    }
                }
                let _ = conn.execute(
                    "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,'',0,0,?13,?13)",
                    rusqlite::params![
                        id,
                        username,
                        ab.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                        hostname,
                        ab.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
                        platform,
                        tags,
                        ab.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
                        user.id,
                        ab.get("forceAlwaysRelay").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
                        ab.get("rdpPort").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("rdpUsername").and_then(|v| v.as_str()).unwrap_or(""),
                        now,
                    ],
                );
            }
            Some(row_id) => {
                let _ = conn.execute(
                    "UPDATE address_books SET id=?1, username=?2, password=?3, hostname=?4, alias=?5, platform=?6, tags=?7, hash=?8, force_always_relay=?9, rdp_port=?10, rdp_username=?11, updated_at=?12 WHERE row_id=?13",
                    rusqlite::params![
                        id,
                        ab.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("platform").and_then(|v| v.as_str()).unwrap_or(""),
                        tags,
                        ab.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("forceAlwaysRelay").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
                        ab.get("rdpPort").and_then(|v| v.as_str()).unwrap_or(""),
                        ab.get("rdpUsername").and_then(|v| v.as_str()).unwrap_or(""),
                        now,
                        row_id,
                    ],
                );
            }
        }
    }
    // 删除不在上传列表中的
    for (row_id, id) in &db_ids {
        if !up_ids.contains_key(id) {
            let _ = conn.execute("DELETE FROM address_books WHERE row_id = ?1", [row_id]);
        }
    }
    // tags 同步：先查全部，删除/更新/新增
    let all_tags: Vec<(i64, String, i64)> = conn
        .prepare("SELECT id, name, color FROM tags WHERE user_id = ?1")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    let mut remain = tc.clone();
    for (tid, name, color) in &all_tags {
        match remain.remove(name) {
            None => {
                let _ = conn.execute("DELETE FROM tags WHERE id = ?1", [tid]);
            }
            Some(new_color) => {
                if new_color != *color {
                    let _ = conn.execute(
                        "UPDATE tags SET color = ?1, updated_at = ?2 WHERE id = ?3",
                        rusqlite::params![new_color, now, tid],
                    );
                }
            }
        }
    }
    for (name, color) in &remain {
        let _ = conn.execute(
            "INSERT INTO tags (name, user_id, color, collection_id, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?4)",
            rusqlite::params![name, user.id, color, now],
        );
    }
    let _ = conn.execute_batch("COMMIT");
    drop(conn);
    Json(Value::Null).into_response()
}

// ══════════════════════════════════════════════════════════════════
// ab personal 系列（guid = gid-uid-cid）
// ══════════════════════════════════════════════════════════════════

fn compose_guid(gid: i64, uid: i64, cid: i64) -> String {
    format!("{}-{}-{}", gid, uid, cid)
}

/// ParseGuid → (gid, uid, cid)；非法 → (0,0,0)
fn parse_guid(guid: &str) -> (i64, i64, i64) {
    let parts: Vec<&str> = guid.split('-').collect();
    if parts.len() < 2 {
        return (0, 0, 0);
    }
    let gid = parts[0].parse().unwrap_or(0);
    let uid = parts[1].parse().unwrap_or(0);
    let cid = if parts.len() == 3 {
        parts[2].parse().unwrap_or(0)
    } else {
        0
    };
    (gid, uid, cid)
}

/// CheckGuid：校验 gid/uid/cid 有效性 → Err(错误码)
fn check_guid(state: &AdminState, cu: &User, guid: &str) -> Result<(i64, i64, i64), &'static str> {
    let (gid, uid, cid) = parse_guid(guid);
    if gid == 0 || uid == 0 {
        return Err("ParamsError");
    }
    let target: User = if cu.id == uid {
        cu.clone()
    } else {
        match crate::api::admin::user_by_id(&state.db, uid) {
            Some(u) if u.id > 0 => u,
            _ => return Err("ParamsError"),
        }
    };
    if target.group_id != gid {
        return Err("ParamsError");
    }
    if cid == 0 && cu.id != uid {
        return Err("ParamsError");
    }
    if cid > 0 {
        let owner: i64 = state
            .db
            .conn()
            .query_row(
                "SELECT user_id FROM address_book_collections WHERE id = ?1",
                [cid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if owner == 0 || owner != uid {
            return Err("ParamsError");
        }
    }
    Ok((gid, uid, cid))
}

/// UserMaxRule（对齐 Go service/addressBook.go）：1=读 2=读写 3=完全控制
fn user_max_rule(state: &AdminState, user: &User, uid: i64, cid: i64) -> i64 {
    if user.id == uid {
        return 3;
    }
    let conn = state.db.conn();
    let mut max: i64 = 0;
    let personal: i64 = conn
        .query_row(
            "SELECT rule FROM address_book_collection_rules WHERE type = 1 AND collection_id = ?1 AND to_id = ?2 LIMIT 1",
            [cid, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if personal > 0 {
        max = personal;
        if max == 3 {
            return 3;
        }
    }
    let group: i64 = conn
        .query_row(
            "SELECT rule FROM address_book_collection_rules WHERE type = 2 AND collection_id = ?1 AND to_id = ?2 LIMIT 1",
            [cid, user.group_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if group > max {
        max = group;
    }
    max
}

fn has_read_privilege(state: &AdminState, user: &User, uid: i64, cid: i64) -> bool {
    user_max_rule(state, user, uid, cid) >= 1
}
fn has_write_privilege(state: &AdminState, user: &User, uid: i64, cid: i64) -> bool {
    user_max_rule(state, user, uid, cid) >= 2
}
fn has_full_control_privilege(state: &AdminState, user: &User, uid: i64, cid: i64) -> bool {
    user_max_rule(state, user, uid, cid) >= 3
}

/// POST /api/ab/personal
async fn handle_ab_personal(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let config = state.config_manager.get().await;
    if config.rustdesk.personal == 1 {
        Json(json!({
            "guid": compose_guid(user.group_id, user.id, 0),
            "name": user.username,
            "rule": 3,
        }))
        .into_response()
    } else {
        Json(Value::Null).into_response()
    }
}

/// POST /api/ab/settings
async fn handle_ab_settings() -> Json<Value> {
    Json(json!({ "max_peer_one_ab": 0 }))
}

/// POST /api/ab/shared/profiles
async fn handle_ab_shared_profiles(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let conn = state.db.conn();
    let mut res: Vec<Value> = Vec::new();
    // 自己的 collections
    let mine: Vec<(i64, String)> = conn
        .prepare(
            "SELECT id, name FROM address_book_collections WHERE user_id = ?1 LIMIT 100 OFFSET 0",
        )
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], |r| Ok((r.get(0)?, r.get(1)?)))
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    for (cid, name) in &mine {
        res.push(json!({
            "guid": compose_guid(user.group_id, user.id, *cid),
            "name": name,
            "owner": user.username,
            "note": "",
            "rule": 3,
        }));
    }
    // 分享给我的（personal type=1 to_id=me；group type=2 to_id=my_group）
    let rules: Vec<(i64, i64, i64)> = conn
        .prepare("SELECT collection_id, rule, user_id FROM address_book_collection_rules WHERE ((type = 1 AND to_id = ?1) OR (type = 2 AND to_id = ?2)) AND rule > 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id, user.group_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .ok()
            .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    // 去重并保留最大 rule
    let mut max_by_cid: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    let mut owner_by_cid: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    for (cid, rule, owner_uid) in &rules {
        let e = max_by_cid.entry(*cid).or_insert(0);
        if *e < *rule {
            *e = *rule;
        }
        owner_by_cid.entry(*cid).or_insert(*owner_uid);
    }
    if !max_by_cid.is_empty() {
        let ids: Vec<i64> = max_by_cid.keys().cloned().collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
        let collections: Vec<(i64, i64, String)> = conn
            .prepare(&format!(
                "SELECT id, user_id, name FROM address_book_collections WHERE id IN ({})",
                placeholders
            ))
            .ok()
            .and_then(|mut stmt| {
                stmt.query_map(params.as_slice(), |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
            })
            .unwrap_or_default();
        for (cid, owner_uid, name) in collections {
            // owner 用户名 + group
            let (ogid, oname) = conn
                .query_row(
                    "SELECT group_id, username FROM users WHERE id = ?1",
                    [owner_uid],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .unwrap_or((0, String::new()));
            if ogid == 0 {
                continue;
            }
            res.push(json!({
                "guid": compose_guid(ogid, owner_uid, cid),
                "name": name,
                "owner": oname,
                "note": "",
                "rule": max_by_cid.get(&cid).cloned().unwrap_or(0),
            }));
        }
    }
    drop(conn);
    Json(json!({ "total": 0, "data": res })).into_response()
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct AbPeersQuery {
    #[serde(default)]
    #[serde(alias = "pageSize")]
    page_size: i64,
    #[serde(default)]
    ab: String,
}

/// POST /api/ab/peers?ab={guid} → {total, data, licensed_devices}
async fn handle_ab_peers(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AbPeersQuery>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &q.ab) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_read_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let conn = state.db.conn();
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE user_id = ?1 AND collection_id = ?2",
            [uid, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let data: Vec<Value> = conn
        .prepare("SELECT * FROM address_books WHERE user_id = ?1 AND collection_id = ?2 LIMIT 1000 OFFSET 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([uid, cid], crate::api::crud::ab_row_to_json)
                .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    drop(conn);
    Json(json!({ "total": total, "data": data, "licensed_devices": 99999 })).into_response()
}

/// POST /api/ab/tags/:guid → TagList（裸数组）
async fn handle_ab_tags(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_read_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let conn = state.db.conn();
    let tags: Vec<Value> = conn
        .prepare("SELECT id, name, user_id, color, collection_id, created_at, updated_at FROM tags WHERE user_id = ?1 AND collection_id = ?2")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([uid, cid], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "user_id": r.get::<_, i64>(2)?,
                    "color": r.get::<_, i64>(3)?,
                    "collection_id": r.get::<_, i64>(4)?,
                    "created_at": crate::db::format_autotime(&r.get::<_, String>(5)?),
                    "updated_at": crate::db::format_autotime(&r.get::<_, String>(6)?),
                }))
            })
            .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    drop(conn);
    Json(json!(tags)).into_response()
}

/// POST /api/ab/peer/add/:guid
async fn handle_ab_peer_add(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_write_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return error_text("ParamsError");
    }
    let mut platform = b
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut username = b
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut hostname = b
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let conn = state.db.conn();
    if platform.is_empty() || username.is_empty() || hostname.is_empty() {
        if let Ok((os, un, hn)) = conn.query_row(
            "SELECT os, username, hostname FROM peers WHERE id = ?1",
            [&id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        ) {
            platform = crate::api::crud::platform_from_os_str(&os);
            username = un;
            hostname = hn;
        }
    }
    let tags = match b.get("tags") {
        Some(Value::Array(_)) => {
            serde_json::to_string(b.get("tags").unwrap()).unwrap_or_else(|_| "[]".into())
        }
        _ => "null".to_string(),
    };
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let res = conn.execute(
        "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,?13,'',0,?14,?14)",
        rusqlite::params![
            id,
            username,
            b.get("password").and_then(|v| v.as_str()).unwrap_or(""),
            hostname,
            b.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
            platform,
            tags,
            b.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
            uid,
            b.get("forceAlwaysRelay").and_then(|v| v.as_bool())
                .or_else(|| b.get("forceAlwaysRelay").and_then(|v| v.as_str()).map(|s| s == "true"))
                .unwrap_or(false) as i64,
            b.get("rdpPort").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("rdpUsername").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("loginName").and_then(|v| v.as_str()).unwrap_or(""),
            cid,
            now,
        ],
    );
    drop(conn);
    if res.is_err() {
        return error_text("OperationFailed");
    }
    plain_text("")
}

/// DELETE /api/ab/peer/:guid —— body 是 id 数组
async fn handle_ab_peer_del(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_full_control_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let ids: Vec<String> = serde_json::from_slice(&body).unwrap_or_default();
    if ids.is_empty() {
        return error_text("ParamsError");
    }
    let conn = state.db.conn();
    for id in &ids {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM address_books WHERE user_id = ?1 AND id = ?2 AND collection_id = ?3",
                rusqlite::params![uid, id, cid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            drop(conn);
            return error_text("ItemNotFound");
        }
    }
    for id in &ids {
        let _ = conn.execute(
            "DELETE FROM address_books WHERE user_id = ?1 AND id = ?2 AND collection_id = ?3",
            rusqlite::params![uid, id, cid],
        );
    }
    drop(conn);
    plain_text("")
}

/// PUT /api/ab/peer/update/:guid —— 允许字段 password/hash/tags/alias
async fn handle_ab_peer_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_write_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let id = match b.get("id") {
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => return error_text("ParamsError"),
        },
        None => return error_text("ParamsError"),
    };
    let conn = state.db.conn();
    let row_id: i64 = conn
        .query_row(
            "SELECT row_id FROM address_books WHERE user_id = ?1 AND id = ?2 AND collection_id = ?3",
            rusqlite::params![uid, id, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if row_id == 0 {
        drop(conn);
        return error_text("ItemNotFound");
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    // 允许字段白名单
    if let Some(v) = b.get("password").and_then(|v| v.as_str()) {
        let _ = conn.execute(
            "UPDATE address_books SET password = ?1, updated_at = ?2 WHERE row_id = ?3",
            rusqlite::params![v, now, row_id],
        );
    }
    if let Some(v) = b.get("hash").and_then(|v| v.as_str()) {
        let _ = conn.execute(
            "UPDATE address_books SET hash = ?1, updated_at = ?2 WHERE row_id = ?3",
            rusqlite::params![v, now, row_id],
        );
    }
    if let Some(v) = b.get("alias").and_then(|v| v.as_str()) {
        let _ = conn.execute(
            "UPDATE address_books SET alias = ?1, updated_at = ?2 WHERE row_id = ?3",
            rusqlite::params![v, now, row_id],
        );
    }
    if let Some(v) = b.get("tags") {
        let tags = match v {
            Value::Array(_) => serde_json::to_string(v).unwrap_or_else(|_| "[]".into()),
            _ => "null".to_string(),
        };
        let _ = conn.execute(
            "UPDATE address_books SET tags = ?1, updated_at = ?2 WHERE row_id = ?3",
            rusqlite::params![tags, now, row_id],
        );
    }
    drop(conn);
    plain_text("")
}

/// POST /api/ab/tag/add/:guid —— body {name, color}
async fn handle_ab_tag_add(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_write_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return error_text("ParamsError");
    }
    let color = b.get("color").and_then(|v| v.as_i64()).unwrap_or(0);
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE user_id = ?1 AND name = ?2 AND collection_id = ?3",
            rusqlite::params![uid, name, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists > 0 {
        drop(conn);
        return error_text("ItemExists");
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let _ = conn.execute(
        "INSERT INTO tags (name, user_id, color, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?5)",
        rusqlite::params![name, uid, color, cid, now],
    );
    drop(conn);
    plain_text("")
}

/// PUT /api/ab/tag/rename/:guid —— body {old, new}
async fn handle_ab_tag_rename(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_write_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let old = b.get("old").and_then(|v| v.as_str()).unwrap_or("");
    let new = b.get("new").and_then(|v| v.as_str()).unwrap_or("");
    let conn = state.db.conn();
    let tid: i64 = conn
        .query_row(
            "SELECT id FROM tags WHERE user_id = ?1 AND name = ?2 AND collection_id = ?3",
            rusqlite::params![uid, old, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if tid == 0 {
        drop(conn);
        return error_text("ItemNotFound");
    }
    let exists_new: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE user_id = ?1 AND name = ?2 AND collection_id = ?3",
            rusqlite::params![uid, new, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists_new > 0 {
        drop(conn);
        return error_text("ItemExists");
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let _ = conn.execute(
        "UPDATE tags SET name = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![new, now, tid],
    );
    drop(conn);
    plain_text("")
}

/// PUT /api/ab/tag/update/:guid —— body {name, color}
async fn handle_ab_tag_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(b): Json<Value>,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_write_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let color = b.get("color").and_then(|v| v.as_i64()).unwrap_or(0);
    let conn = state.db.conn();
    let tid: i64 = conn
        .query_row(
            "SELECT id FROM tags WHERE user_id = ?1 AND name = ?2 AND collection_id = ?3",
            rusqlite::params![uid, name, cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if tid == 0 {
        drop(conn);
        return error_text("ItemNotFound");
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string();
    let _ = conn.execute(
        "UPDATE tags SET color = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![color, now, tid],
    );
    drop(conn);
    plain_text("")
}

/// DELETE /api/ab/tag/:guid —— body 是 name 数组
async fn handle_ab_tag_del(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (_, uid, cid) = match check_guid(&state, &user, &guid) {
        Ok(x) => x,
        Err(msg) => return error_text(msg),
    };
    if !has_full_control_privilege(&state, &user, uid, cid) {
        return error_text("NoAccess");
    }
    let names: Vec<String> = serde_json::from_slice(&body).unwrap_or_default();
    let conn = state.db.conn();
    for name in &names {
        let tid: i64 = conn
            .query_row(
                "SELECT id FROM tags WHERE user_id = ?1 AND name = ?2 AND collection_id = ?3",
                rusqlite::params![uid, name, cid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if tid == 0 {
            drop(conn);
            return error_text("ItemNotFound");
        }
        let _ = conn.execute("DELETE FROM tags WHERE id = ?1", [tid]);
    }
    drop(conn);
    plain_text("")
}

// ══════════════════════════════════════════════════════════════════
// web client
// ══════════════════════════════════════════════════════════════════

/// POST /api/shared-peer（免登录，share_token）
async fn handle_shared_peer(State(state): State<AdminState>, Json(b): Json<Value>) -> Json<Value> {
    let token = b.get("share_token").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() {
        return common::fail(101, "share_token is required");
    }
    let config = state.config_manager.get().await;
    let conn = state.db.conn();
    let sr: Option<(i64, i64, String, String, i64, String)> = conn
        .query_row(
            "SELECT id, user_id, peer_id, password, expire, created_at FROM share_records WHERE share_token = ?1",
            [token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .ok();
    let (_id, user_id, peer_id, password, expire, created_at) = match sr {
        Some(x) if x.0 > 0 => x,
        _ => {
            drop(conn);
            return common::fail(101, "share not found");
        }
    };
    if expire != 0 {
        // created_at + expire 秒 → 过期判断（created_at 是 "YYYY-MM-DD HH:MM:SS..."）
        if let Ok(created) = chrono::NaiveDateTime::parse_from_str(
            &created_at[0..19.min(created_at.len())],
            "%Y-%m-%d %H:%M:%S",
        ) {
            let expire_at = created + chrono::Duration::seconds(expire);
            if expire_at < chrono::Utc::now().naive_utc() {
                drop(conn);
                return common::fail(101, "share expired");
            }
        }
    }
    // 查 address_book
    let ab: Option<(String, String)> = conn
        .query_row(
            "SELECT username, hostname FROM address_books WHERE user_id = ?1 AND id = ?2",
            rusqlite::params![user_id, peer_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (username, hostname) = match ab {
        Some(x) => x,
        None => {
            drop(conn);
            return common::fail(101, "peer not found");
        }
    };
    drop(conn);
    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    common::success(json!({
        "id_server": config.rustdesk.id_server,
        "key": config.rustdesk.key,
        "peer": {
            "view-style": "shrink",
            "tm": now_ns,
            "info": {
                "username": username,
                "hostname": hostname,
                "platform": "",
                "hash": "",
                "id": peer_id,
            },
            "tmppwd": password,
        },
    }))
}

/// POST /api/server-config（需登录；web_client==1 时才可用）
async fn handle_server_config(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let config = state.config_manager.get().await;
    if config.app.web_client != 1 {
        return error_text("WebClientDisabled");
    }
    drop(config);
    let user = match auth(&state, &headers).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let (id_server, key) = {
        let config = state.config_manager.get().await;
        (
            config.rustdesk.id_server.clone(),
            config.rustdesk.key.clone(),
        )
    };
    let conn = state.db.conn();
    let mut peers = serde_json::Map::new();
    let abs: Vec<(String, String, String, String, String)> = conn
        .prepare("SELECT id, username, hostname, platform, hash FROM address_books WHERE user_id = ?1 AND collection_id = 0 LIMIT 100 OFFSET 0")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .ok()
            .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    let day_ago_ns = (crate::db::now_unix() - 86400) * 1_000_000_000;
    for (id, username, hostname, platform, hash) in abs {
        peers.insert(
            id.clone(),
            json!({
                "view-style": "shrink",
                "tm": day_ago_ns,
                "info": {
                    "username": username,
                    "hostname": hostname,
                    "platform": platform,
                    "hash": hash,
                    "id": id,
                },
                "tmppwd": "",
            }),
        );
    }
    common::success(json!({
        "id_server": id_server,
        "key": key,
        "peers": Value::Object(peers),
    }))
    .into_response()
}

/// POST /api/server-config-v2（需登录）
async fn handle_server_config_v2(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let config = state.config_manager.get().await;
    if config.app.web_client != 1 {
        return error_text("WebClientDisabled");
    }
    drop(config);
    if let Err(resp) = auth(&state, &headers).await {
        return resp;
    }
    let config = state.config_manager.get().await;
    common::success(json!({
        "id_server": config.rustdesk.id_server,
        "key": config.rustdesk.key,
    }))
    .into_response()
}
