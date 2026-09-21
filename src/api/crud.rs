//! 管理面全量 CRUD（对齐 Go http/controller/admin/* + service/*）
//!
//! 所有 handler 内部先做 backend_user_auth；admin 组额外校验 is_admin。
//! 管理分页统一 {code:0, message, data:{page,total,page_size,list}}。
//! GORM `Updates(struct)` 只更新非零字段；`Select("*").Omit("created_at")` 全字段更新。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::admin::AdminState;
use crate::api::common;
use crate::auth;
use crate::models::User;

// ─────────────────────────── 通用辅助 ───────────────────────────

/// 管理分页封装：{code:0,message,data:{page,total,page_size,list}}
pub fn page_ok(page: i64, total: i64, page_size: i64, list: Value) -> Json<Value> {
    common::success(json!({
        "page": page,
        "total": total,
        "page_size": page_size,
        "list": list,
    }))
}

#[derive(Debug, Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
}

/// 取分页参数，规范化（对齐 Go service.Paginate：page==0→1，pageSize==0→10）
fn page_args(q: &PageQuery) -> (i64, i64) {
    let page = if q.page <= 0 { 1 } else { q.page };
    let size = if q.page_size <= 0 { 10 } else { q.page_size };
    (page, size)
}

/// 管理面鉴权（仅登录）→ (user, token)。须在 handler 内 await config 后调用。
async fn auth_user(
    state: &AdminState,
    headers: &HeaderMap,
) -> Result<(User, String), (i64, &'static str)> {
    let config = state.config_manager.get().await;
    auth::backend_user_auth(&state.db, headers, config.app.token_expire_secs)
}

/// 管理面鉴权 + 管理员校验
async fn auth_admin(state: &AdminState, headers: &HeaderMap) -> Result<User, (i64, &'static str)> {
    let (user, _) = auth_user(state, headers).await?;
    if !user.is_admin() {
        // 对齐 Go AdminPrivilege：403 NoAccess
        return Err((403, "NoAccess"));
    }
    Ok(user)
}

fn auth_err(e: (i64, &'static str), headers: &HeaderMap) -> Json<Value> {
    common::fail_h(e.0, e.1, headers)
}

/// 当前时间 SQL 字符串（对齐 GORM 写入的 RFC3339 长格式；查询端统一截前 19 位比较）
pub fn now_sql() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f+00:00")
        .to_string()
}

/// 查询行数
fn count(
    conn: &rusqlite::Connection,
    table: &str,
    where_clause: &str,
    params: &[&dyn rusqlite::ToSql],
) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {} {}", table, where_clause);
    conn.query_row(&sql, params, |r| r.get::<_, i64>(0))
        .unwrap_or(0)
}

/// LIKE 参数
fn like(v: &str) -> String {
    format!("%{}%", v)
}

// ─────────────────────────── user ───────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct UserQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub user_id: i64,
}

/// GET /api/admin/user/list
pub async fn handle_user_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
) -> Json<Value> {
    let user = match auth_admin(&state, &headers).await {
        Ok(u) => u,
        Err(e) => return auth_err(e, &headers),
    };
    let _ = user;
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let (wc, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if !q.username.is_empty() {
        (
            "WHERE username LIKE ?1".into(),
            vec![Box::new(like(&q.username))],
        )
    } else {
        (String::new(), vec![])
    };
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let total = count(&conn, "users", &wc, &p);
    let offset = (page - 1) * size;
    let sql = format!(
        "SELECT * FROM users {} ORDER BY id LIMIT {} OFFSET {}",
        wc, size, offset
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => return common::fail_msg(101, format!("OperationFailed{}", e)),
    };
    let rows = stmt
        .query_map(p.as_slice(), crate::api::admin::row_to_user)
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    drop(conn);
    let list: Vec<Value> = rows
        .iter()
        .map(|u| serde_json::to_value(u).unwrap_or(Value::Null))
        .collect();
    page_ok(page, total, size, json!(list))
}

/// GET /api/admin/user/detail/:id
pub async fn handle_user_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    match crate::api::admin::user_by_id(&state.db, iid) {
        Some(u) if u.id > 0 => common::success(serde_json::to_value(&u).unwrap_or(Value::Null)),
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/user/create（UserForm 无 password 字段；创建时密码为空 bcrypt）
pub async fn handle_user_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let username = b.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let group_id = b.get("group_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if username.len() < 2 || username.len() > 32 || group_id == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    // IsUsernameExists → "UsernameExists"（拼接为 OperationFailed+err）
    let conn = state.db.conn();
    let formatted = username.replace(' ', "").to_lowercase();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE username = ?1",
            [&formatted],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists > 0 {
        return common::fail_msg(101, "OperationFailedUsernameExists".to_string());
    }
    let is_admin = b.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
    let status = b.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    if status < 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let email = b.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let nickname = b.get("nickname").and_then(|v| v.as_str()).unwrap_or("");
    let avatar = b.get("avatar").and_then(|v| v.as_str()).unwrap_or("");
    let remark = b.get("remark").and_then(|v| v.as_str()).unwrap_or("");
    let hash = crate::utils::hash_password("");
    let res = conn.execute(
        "INSERT INTO users (username, email, password, nickname, avatar, group_id, is_admin, status, remark, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
        rusqlite::params![formatted, email, hash, nickname, avatar, group_id, is_admin as i64, status, remark, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/user/update（GORM Updates 非零字段语义；最后一个 admin 保护）
pub async fn handle_user_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let cur = match auth_admin(&state, &headers).await {
        Ok(u) => u,
        Err(e) => return auth_err(e, &headers),
    };
    let uid = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let username = b.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let group_id = b.get("group_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if uid == 0 || username.len() < 2 || username.len() > 32 || group_id == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let existing = match conn.query_row(
        "SELECT * FROM users WHERE id = ?1",
        [uid],
        crate::api::admin::row_to_user,
    ) {
        Ok(u) => u,
        Err(_) => {
            drop(conn);
            return common::fail_h(101, "ItemNotFound", &headers);
        }
    };
    drop(conn);
    // 最后一个 admin 保护（对齐 Go UserService.Update）
    if existing.is_admin() {
        let admin_count = {
            let conn = state.db.conn();
            let c: i64 = conn
                .query_row("SELECT COUNT(*) FROM users WHERE is_admin = 1", [], |r| {
                    r.get(0)
                })
                .unwrap_or(0);
            drop(conn);
            c
        };
        let new_is_admin = b.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);
        let new_status = b.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
        if admin_count <= 1 && (!new_is_admin || new_status == 2) {
            return common::fail_msg(
                101,
                "The last admin user cannot be disabled or demoted".to_string(),
            );
        }
    }
    let _ = cur;
    // 非零字段更新
    let conn = state.db.conn();
    let _ = conn.execute(
        "UPDATE users SET username=?1, email=?2, nickname=?3, avatar=?4, group_id=?5, is_admin=?6, status=?7, remark=?8, updated_at=?9 WHERE id=?10",
        rusqlite::params![
            username.replace(' ', "").to_lowercase(),
            b.get("email").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("nickname").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("avatar").and_then(|v| v.as_str()).unwrap_or(""),
            group_id,
            b.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
            b.get("status").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("remark").and_then(|v| v.as_str()).unwrap_or(""),
            now_sql(),
            uid
        ],
    );
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/user/delete（最后一个 admin 不能删；事务级联删）
pub async fn handle_user_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let uid = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if uid <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let existing = match conn.query_row(
        "SELECT * FROM users WHERE id = ?1",
        [uid],
        crate::api::admin::row_to_user,
    ) {
        Ok(u) => u,
        Err(_) => {
            drop(conn);
            return common::fail_h(101, "ItemNotFound", &headers);
        }
    };
    if existing.is_admin() {
        let admin_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE is_admin = 1", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        if admin_count <= 1 {
            drop(conn);
            return common::fail_msg(101, "The last admin user cannot be deleted".to_string());
        }
    }
    let tx_res = conn.execute_batch("BEGIN");
    if tx_res.is_err() {
        drop(conn);
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    let _ = conn.execute("DELETE FROM users WHERE id = ?1", [uid]);
    let _ = conn.execute("DELETE FROM user_thirds WHERE user_id = ?1", [uid]);
    let _ = conn.execute("DELETE FROM address_books WHERE user_id = ?1", [uid]);
    let _ = conn.execute(
        "DELETE FROM address_book_collections WHERE user_id = ?1",
        [uid],
    );
    let _ = conn.execute(
        "DELETE FROM address_book_collection_rules WHERE user_id = ?1",
        [uid],
    );
    let _ = conn.execute_batch("COMMIT");
    drop(conn);
    // EraseUserId（失败仅警告，仍成功）
    let conn = state.db.conn();
    let _ = conn.execute("UPDATE peers SET user_id = 0 WHERE user_id = ?1", [uid]);
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/user/changePwd
pub async fn handle_user_change_pwd(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let uid = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let password = b.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if uid == 0 || password.len() < 4 || password.len() > 32 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM users WHERE id = ?1", [uid], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let hash = crate::utils::hash_password(password);
    let _ = conn.execute(
        "UPDATE users SET password = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![hash, now_sql(), uid],
    );
    // FlushToken：清空该用户全部 token
    let _ = conn.execute("DELETE FROM user_tokens WHERE user_id = ?1", [uid]);
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/user/groupUsers 的 groups 部分（裸数组）
pub fn list_groups_json(state: &AdminState) -> Value {
    let conn = state.db.conn();
    let mut stmt = match conn.prepare("SELECT * FROM groups ORDER BY id") {
        Ok(s) => s,
        Err(_) => return json!([]),
    };
    let rows = stmt
        .query_map([], row_to_group)
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    drop(conn);
    json!(rows)
}

/// POST /api/admin/user/groupUsers 的 users 部分（裸数组）
pub fn list_all_users_json(state: &AdminState) -> Value {
    let conn = state.db.conn();
    let mut stmt = match conn.prepare("SELECT * FROM users ORDER BY id") {
        Ok(s) => s,
        Err(_) => return json!([]),
    };
    let rows = stmt
        .query_map([], crate::api::admin::row_to_user)
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    drop(conn);
    json!(rows)
}

fn row_to_group(row: &rusqlite::Row) -> rusqlite::Result<crate::models::Group> {
    Ok(crate::models::Group {
        id: row.get(0)?,
        name: row.get(1)?,
        type_: row.get(2)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(3)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(4)?),
    })
}

// ─────────────────────────── group / device_group ───────────────────────────

/// GET /api/admin/group/list
pub async fn handle_group_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&q);
    let conn = state.db.conn();
    let total = count(&conn, "groups", "", &[]);
    let offset = (page - 1) * size;
    let mut stmt = match conn.prepare(&format!(
        "SELECT * FROM groups ORDER BY id LIMIT {} OFFSET {}",
        size, offset
    )) {
        Ok(s) => s,
        Err(_) => {
            return common::fail_msg(101, "OperationFailed".to_string());
        }
    };
    let rows = stmt
        .query_map([], row_to_group)
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// GET /api/admin/group/detail/:id
pub async fn handle_group_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let g = conn
        .query_row("SELECT * FROM groups WHERE id = ?1", [iid], row_to_group)
        .ok();
    drop(conn);
    match g {
        Some(g) if g.id > 0 => common::success(serde_json::to_value(&g).unwrap_or(Value::Null)),
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/group/create
pub async fn handle_group_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let type_ = b.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO groups (name, type, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        rusqlite::params![name, type_, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/group/update（非零字段更新）
pub async fn handle_group_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id == 0 || name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let type_ = b.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
    if type_ != 0 {
        let _ = conn.execute(
            "UPDATE groups SET name=?1, type=?2, updated_at=?3 WHERE id=?4",
            rusqlite::params![name, type_, now_sql(), id],
        );
    } else {
        let _ = conn.execute(
            "UPDATE groups SET name=?1, updated_at=?2 WHERE id=?3",
            rusqlite::params![name, now_sql(), id],
        );
    }
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/group/delete
pub async fn handle_group_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute("DELETE FROM groups WHERE id = ?1", [id]);
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

fn row_to_device_group(row: &rusqlite::Row) -> rusqlite::Result<crate::models::DeviceGroup> {
    Ok(crate::models::DeviceGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(2)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(3)?),
    })
}

/// GET /api/admin/device_group/list
pub async fn handle_device_group_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&q);
    let conn = state.db.conn();
    let total = count(&conn, "device_groups", "", &[]);
    let offset = (page - 1) * size;
    let mut stmt = match conn.prepare(&format!(
        "SELECT * FROM device_groups ORDER BY id LIMIT {} OFFSET {}",
        size, offset
    )) {
        Ok(s) => s,
        Err(_) => {
            return common::fail_msg(101, "OperationFailed".to_string());
        }
    };
    let rows = stmt
        .query_map([], row_to_device_group)
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// GET /api/admin/device_group/detail/:id
pub async fn handle_device_group_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let g = conn
        .query_row(
            "SELECT * FROM device_groups WHERE id = ?1",
            [iid],
            row_to_device_group,
        )
        .ok();
    drop(conn);
    match g {
        Some(g) if g.id > 0 => common::success(serde_json::to_value(&g).unwrap_or(Value::Null)),
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/device_group/create
pub async fn handle_device_group_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO device_groups (name, created_at, updated_at) VALUES (?1, ?2, ?2)",
        rusqlite::params![name, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/device_group/update
pub async fn handle_device_group_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id == 0 || name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM device_groups WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let _ = conn.execute(
        "UPDATE device_groups SET name=?1, updated_at=?2 WHERE id=?3",
        rusqlite::params![name, now_sql(), id],
    );
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/device_group/delete
pub async fn handle_device_group_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM device_groups WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute("DELETE FROM device_groups WHERE id = ?1", [id]);
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

// ─────────────────────────── tag ───────────────────────────

fn row_to_tag(row: &rusqlite::Row) -> rusqlite::Result<crate::models::Tag> {
    Ok(crate::models::Tag {
        id: row.get(0)?,
        name: row.get(1)?,
        user_id: row.get(2)?,
        color: row.get(3)?,
        collection_id: row.get(4)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(5)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(6)?),
    })
}

fn tag_json(t: &crate::models::Tag) -> Value {
    // Preload Collection（id,name；不存在则 null）
    json!({
        "id": t.id,
        "name": t.name,
        "user_id": t.user_id,
        "color": t.color,
        "collection_id": t.collection_id,
        "collection": collection_json_opt(t.collection_id),
        "created_at": t.created_at,
        "updated_at": t.updated_at,
    })
}

fn collection_json_opt(cid: i64) -> Value {
    if cid == 0 {
        return Value::Null;
    }
    COLLECTION_CACHE.with(|c| {
        if let Some(v) = c.borrow().get(&cid) {
            return v.clone();
        }
        Value::Null
    })
}

thread_local! {
    /// 请求级 collection 预载缓存（tag/ab 列表内设置）
    static COLLECTION_CACHE: std::cell::RefCell<std::collections::HashMap<i64, Value>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

fn load_collection_cache(conn: &rusqlite::Connection, cids: &[i64]) {
    let uniq: std::collections::HashSet<i64> = cids.iter().cloned().filter(|c| *c > 0).collect();
    let ids: Vec<i64> = uniq.into_iter().collect();
    if ids.is_empty() {
        return;
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT id, name FROM address_book_collections WHERE id IN ({})",
        placeholders
    );
    let params: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
    COLLECTION_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        if let Ok(mut stmt) = conn.prepare(&sql) {
            if let Ok(rows) = stmt.query_map(params.as_slice(), |r| {
                Ok(json!({"id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?}))
            }) {
                for row in rows.flatten() {
                    if let Some(id) = row.get("id").and_then(|v| v.as_i64()) {
                        cache.insert(id, row);
                    }
                }
            }
        }
    });
}

#[derive(Debug, Deserialize, Default)]
pub struct TagQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub collection_id: Option<i64>,
}

/// GET /api/admin/tag/list
pub async fn handle_tag_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<TagQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    if q.user_id > 0 {
        params.push(Box::new(q.user_id));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    }
    if let Some(cid) = q.collection_id {
        if cid >= 0 {
            params.push(Box::new(cid));
            if wc.is_empty() {
                wc.push_str(" WHERE");
            } else {
                wc.push_str(" AND");
            }
            wc.push_str(&format!(" collection_id = ?{}", params.len()));
        }
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "tags", &wc, &p);
    let offset = (page - 1) * size;
    let sql = format!(
        "SELECT * FROM tags {} ORDER BY id LIMIT {} OFFSET {}",
        wc, size, offset
    );
    let rows = conn
        .prepare(&sql)
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_tag)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    load_collection_cache(
        &state.db.conn(),
        &rows.iter().map(|t| t.collection_id).collect::<Vec<_>>(),
    );
    let list: Vec<Value> = rows.iter().map(tag_json).collect();
    page_ok(page, total, size, json!(list))
}

/// GET /api/admin/tag/detail/:id（非 admin 只能看自己的）
pub async fn handle_tag_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(u) => u,
        Err(e) => return auth_err(e, &headers),
    };
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let t = conn
        .query_row("SELECT * FROM tags WHERE id = ?1", [iid], row_to_tag)
        .ok();
    drop(conn);
    match t {
        Some(t) if t.id > 0 => {
            if !user.is_admin() && t.user_id != user.id {
                return common::fail_h(101, "NoAccess", &headers);
            }
            load_collection_cache(&state.db.conn(), &[t.collection_id]);
            common::success(tag_json(&t))
        }
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/tag/create
pub async fn handle_tag_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let color = b.get("color").and_then(|v| v.as_i64()).unwrap_or(0);
    let user_id = b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let collection_id = b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    if user_id == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO tags (name, user_id, color, collection_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![name, user_id, color, collection_id, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/tag/update（Select("*").Omit("created_at") 全字段更新）
pub async fn handle_tag_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id == 0 || name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM tags WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let _ = conn.execute(
        "UPDATE tags SET name=?1, user_id=?2, color=?3, collection_id=?4, updated_at=?5 WHERE id=?6",
        rusqlite::params![
            name,
            b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("color").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0),
            now_sql(),
            id
        ],
    );
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/tag/delete
pub async fn handle_tag_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM tags WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute("DELETE FROM tags WHERE id = ?1", [id]);
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

// ─────────────────────────── address_book ───────────────────────────

fn row_to_address_book(row: &rusqlite::Row) -> rusqlite::Result<crate::models::AddressBook> {
    Ok(crate::models::AddressBook {
        row_id: row.get(0)?,
        id: row.get(1)?,
        username: row.get(2)?,
        password: row.get(3)?,
        hostname: row.get(4)?,
        alias: row.get(5)?,
        platform: row.get(6)?,
        tags: crate::db::normalize_autojson(&row.get::<_, String>(7)?),
        hash: row.get(8)?,
        user_id: row.get(9)?,
        force_always_relay: row.get::<_, i64>(10)? != 0,
        rdp_port: row.get(11)?,
        rdp_username: row.get(12)?,
        online: row.get::<_, i64>(13)? != 0,
        login_name: row.get(14)?,
        same_server: row.get::<_, i64>(15)? != 0,
        collection_id: row.get(16)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(17)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(18)?),
    })
}

/// 客户端 ab 列表用：rusqlite 行 → AddressBook JSON（SELECT * 列序）
pub fn ab_row_to_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let ab = row_to_address_book(row)?;
    Ok(json!({
        "row_id": ab.row_id, "id": ab.id, "username": ab.username, "password": ab.password,
        "hostname": ab.hostname, "alias": ab.alias, "platform": ab.platform,
        "tags": serde_json::from_str::<Value>(&ab.tags).unwrap_or(json!([])),
        "hash": ab.hash, "user_id": ab.user_id, "forceAlwaysRelay": ab.force_always_relay,
        "rdpPort": ab.rdp_port, "rdpUsername": ab.rdp_username, "online": ab.online,
        "loginName": ab.login_name, "sameServer": ab.same_server, "collection_id": ab.collection_id,
        "created_at": ab.created_at, "updated_at": ab.updated_at,
    }))
}

fn ab_json(ab: &crate::models::AddressBook) -> Value {
    json!({
        "row_id": ab.row_id,
        "id": ab.id,
        "username": ab.username,
        "password": ab.password,
        "hostname": ab.hostname,
        "alias": ab.alias,
        "platform": ab.platform,
        "tags": serde_json::from_str::<Value>(&ab.tags).unwrap_or(json!([])),
        "hash": ab.hash,
        "user_id": ab.user_id,
        "forceAlwaysRelay": ab.force_always_relay,
        "rdpPort": ab.rdp_port,
        "rdpUsername": ab.rdp_username,
        "online": ab.online,
        "loginName": ab.login_name,
        "sameServer": ab.same_server,
        "collection_id": ab.collection_id,
        "collection": collection_json_opt(ab.collection_id),
        "created_at": ab.created_at,
        "updated_at": ab.updated_at,
    })
}

/// tags []string → JSON 字符串（对齐 AddressBookForm.ToAddressBook）
pub fn tags_to_json(tags: Option<&Value>) -> String {
    match tags {
        Some(v @ Value::Array(_)) => serde_json::to_string(v).unwrap_or_else(|_| "[]".into()),
        _ => "null".to_string(),
    }
}

fn check_collection_owner(conn: &rusqlite::Connection, uid: i64, cid: i64) -> bool {
    conn.query_row(
        "SELECT user_id FROM address_book_collections WHERE id = ?1",
        [cid],
        |r| r.get::<_, i64>(0),
    )
    .map(|owner| owner == uid)
    .unwrap_or(false)
}

#[derive(Debug, Deserialize, Default)]
pub struct AddressBookQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub collection_id: Option<i64>,
}

pub fn ab_list(
    state: &AdminState,
    q: &AddressBookQuery,
    force_user_id: Option<i64>,
) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    if let Some(uid) = force_user_id {
        params.push(Box::new(uid));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    } else if q.user_id > 0 {
        params.push(Box::new(q.user_id));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    }
    if !q.id.is_empty() {
        params.push(Box::new(like(&q.id)));
        wc.push_str(&format!(
            "{} id LIKE ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            params.len()
        ));
    }
    if !q.username.is_empty() {
        params.push(Box::new(like(&q.username)));
        wc.push_str(&format!(
            "{} username LIKE ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            params.len()
        ));
    }
    if !q.hostname.is_empty() {
        params.push(Box::new(like(&q.hostname)));
        wc.push_str(&format!(
            "{} hostname LIKE ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            params.len()
        ));
    }
    if let Some(cid) = q.collection_id {
        if cid >= 0 {
            params.push(Box::new(cid));
            wc.push_str(&format!(
                "{} collection_id = ?{}",
                if wc.is_empty() { " WHERE" } else { " AND" },
                params.len()
            ));
        }
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "address_books", &wc, &p);
    let offset = (page - 1) * size;
    let sql = format!(
        "SELECT * FROM address_books {} ORDER BY row_id LIMIT {} OFFSET {}",
        wc, size, offset
    );
    let rows = conn
        .prepare(&sql)
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_address_book)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    load_collection_cache(
        &state.db.conn(),
        &rows.iter().map(|t| t.collection_id).collect::<Vec<_>>(),
    );
    let list: Vec<Value> = rows.iter().map(ab_json).collect();
    page_ok(page, total, size, json!(list))
}

// ─────────────────────────── login_log / audit ───────────────────────────

fn row_to_login_log(row: &rusqlite::Row) -> rusqlite::Result<crate::models::LoginLog> {
    Ok(crate::models::LoginLog {
        id: row.get(0)?,
        user_id: row.get(1)?,
        client: row.get(2)?,
        device_id: row.get(3)?,
        uuid: row.get(4)?,
        ip: row.get(5)?,
        type_: row.get(6)?,
        platform: row.get(7)?,
        user_token_id: row.get(8)?,
        is_deleted: row.get(9)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(10)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct LoginLogQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
}

/// GET /api/admin/login_log/list
pub async fn handle_login_log_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<LoginLogQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let (wc, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if q.user_id > 0 {
        ("WHERE user_id = ?1".into(), vec![Box::new(q.user_id)])
    } else {
        (String::new(), vec![])
    };
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "login_logs", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM login_logs {} ORDER BY id DESC LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_login_log)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// POST /api/admin/login_log/delete
pub async fn handle_login_log_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM login_logs WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute("DELETE FROM login_logs WHERE id = ?1", [id]);
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/login_log/batchDelete
pub async fn handle_login_log_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let params: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
    let res = conn.execute(
        &format!("DELETE FROM login_logs WHERE id IN ({})", placeholders),
        params.as_slice(),
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

fn row_to_audit_conn(row: &rusqlite::Row) -> rusqlite::Result<crate::models::AuditConn> {
    Ok(crate::models::AuditConn {
        id: row.get(0)?,
        action: row.get(1)?,
        conn_id: row.get(2)?,
        peer_id: row.get(3)?,
        from_peer: row.get(4)?,
        from_name: row.get(5)?,
        ip: row.get(6)?,
        session_id: row.get(7)?,
        type_: row.get(8)?,
        uuid: row.get(9)?,
        close_time: row.get(10)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(12)?),
    })
}

fn row_to_audit_file(row: &rusqlite::Row) -> rusqlite::Result<crate::models::AuditFile> {
    Ok(crate::models::AuditFile {
        id: row.get(0)?,
        from_peer: row.get(1)?,
        info: row.get(2)?,
        is_file: row.get::<_, i64>(3)? != 0,
        path: row.get(4)?,
        peer_id: row.get(5)?,
        type_: row.get(6)?,
        uuid: row.get(7)?,
        ip: row.get(8)?,
        num: row.get(9)?,
        from_name: row.get(10)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(12)?),
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub from_peer: String,
}

fn audit_list(
    state: &AdminState,
    q: &AuditQuery,
    table: &str,
    mapper: fn(&rusqlite::Row) -> rusqlite::Result<serde_json::Value>,
) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    if !q.peer_id.is_empty() {
        params.push(Box::new(like(&q.peer_id)));
        wc.push_str(&format!(" WHERE peer_id LIKE ?{}", params.len()));
    }
    if !q.from_peer.is_empty() {
        params.push(Box::new(like(&q.from_peer)));
        wc.push_str(&format!(
            "{} from_peer LIKE ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            params.len()
        ));
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, table, &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM {} {} ORDER BY id DESC LIMIT {} OFFSET {}",
            table, wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), mapper)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

fn audit_conn_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let ac = row_to_audit_conn(row)?;
    Ok(json!({
        "id": ac.id, "action": ac.action, "conn_id": ac.conn_id, "peer_id": ac.peer_id,
        "from_peer": ac.from_peer, "from_name": ac.from_name, "ip": ac.ip,
        "session_id": ac.session_id, "type": ac.type_, "uuid": ac.uuid,
        "close_time": ac.close_time, "created_at": ac.created_at, "updated_at": ac.updated_at,
    }))
}

fn audit_file_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let af = row_to_audit_file(row)?;
    Ok(json!({
        "id": af.id, "from_peer": af.from_peer, "info": af.info, "is_file": af.is_file,
        "path": af.path, "peer_id": af.peer_id, "type": af.type_, "uuid": af.uuid,
        "ip": af.ip, "num": af.num, "from_name": af.from_name,
        "created_at": af.created_at, "updated_at": af.updated_at,
    }))
}

/// GET /api/admin/audit_conn/list
pub async fn handle_audit_conn_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    audit_list(&state, &q, "audit_conns", audit_conn_json)
}

/// GET /api/admin/audit_file/list
pub async fn handle_audit_file_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    audit_list(&state, &q, "audit_files", audit_file_json)
}

/// 通用单条/批量删除
fn delete_by_ids(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
    table: &str,
    single_key: &str,
) -> Json<Value> {
    let conn = state.db.conn();
    if let Some(id) = b.get(single_key).and_then(|v| v.as_i64()) {
        // 单条
        if id <= 0 {
            drop(conn);
            return common::fail_h(101, "ParamsError", headers);
        }
        let exists: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {} WHERE id = ?1", table),
                [id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            drop(conn);
            return common::fail_h(101, "ItemNotFound", headers);
        }
        let res = conn.execute(&format!("DELETE FROM {} WHERE id = ?1", table), [id]);
        drop(conn);
        if res.is_err() {
            return common::fail_msg(101, "OperationFailed".to_string());
        }
        return common::success(Value::Null);
    }
    drop(conn);
    common::fail_h(101, "ParamsError", headers)
}

fn batch_delete_ids(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
    table: &str,
) -> Json<Value> {
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return common::fail_h(101, "ParamsError", headers);
    }
    let conn = state.db.conn();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let params: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
    let res = conn.execute(
        &format!("DELETE FROM {} WHERE id IN ({})", table, placeholders),
        params.as_slice(),
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/audit_conn/delete
pub async fn handle_audit_conn_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    delete_by_ids(&state, &headers, &b, "audit_conns", "id")
}

/// POST /api/admin/audit_conn/batchDelete
pub async fn handle_audit_conn_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    batch_delete_ids(&state, &headers, &b, "audit_conns")
}

/// POST /api/admin/audit_file/delete
pub async fn handle_audit_file_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    delete_by_ids(&state, &headers, &b, "audit_files", "id")
}

/// POST /api/admin/audit_file/batchDelete
pub async fn handle_audit_file_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    batch_delete_ids(&state, &headers, &b, "audit_files")
}

// ─────────────────────────── address_book_collection / rule ───────────────────────────

fn row_to_abc(row: &rusqlite::Row) -> rusqlite::Result<crate::models::AddressBookCollection> {
    Ok(crate::models::AddressBookCollection {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(3)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(4)?),
    })
}

fn row_to_abcr(row: &rusqlite::Row) -> rusqlite::Result<crate::models::AddressBookCollectionRule> {
    Ok(crate::models::AddressBookCollectionRule {
        id: row.get(0)?,
        user_id: row.get(1)?,
        collection_id: row.get(2)?,
        rule: row.get(3)?,
        type_: row.get(4)?,
        to_id: row.get(5)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(6)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(7)?),
    })
}

fn abcr_json(r: &crate::models::AddressBookCollectionRule) -> Value {
    json!({
        "id": r.id, "user_id": r.user_id, "collection_id": r.collection_id,
        "rule": r.rule, "type": r.type_, "to_id": r.to_id,
        "created_at": r.created_at, "updated_at": r.updated_at,
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct AbcQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
}

#[derive(Debug, Deserialize, Default)]
pub struct AbcrQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
    #[serde(default)]
    pub collection_id: i64,
}

pub fn abc_list(state: &AdminState, q: &AbcQuery, force_user_id: Option<i64>) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let uid = force_user_id.unwrap_or(q.user_id);
    let (wc, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if uid > 0 {
        ("WHERE user_id = ?1".into(), vec![Box::new(uid)])
    } else {
        (String::new(), vec![])
    };
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "address_book_collections", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM address_book_collections {} ORDER BY id LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_abc)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// GET /api/admin/address_book_collection/list
pub async fn handle_abc_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AbcQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    abc_list(&state, &q, None)
}

/// GET /api/admin/address_book_collection/detail/:id
pub async fn handle_abc_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let c = conn
        .query_row(
            "SELECT * FROM address_book_collections WHERE id = ?1",
            [iid],
            row_to_abc,
        )
        .ok();
    drop(conn);
    match c {
        Some(c) if c.id > 0 => common::success(serde_json::to_value(&c).unwrap_or(Value::Null)),
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/address_book_collection/create
pub async fn handle_abc_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let user_id = b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if name.is_empty() || user_id == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO address_book_collections (user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        rusqlite::params![user_id, name, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/address_book_collection/update（非零字段）
pub async fn handle_abc_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id == 0 || name.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collections WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let _ = conn.execute(
        "UPDATE address_book_collections SET name=?1, updated_at=?2 WHERE id=?3",
        rusqlite::params![name, now_sql(), id],
    );
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/address_book_collection/delete（级联删 rules + address_books）
pub async fn handle_abc_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collections WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let _ = conn.execute_batch("BEGIN");
    let _ = conn.execute(
        "DELETE FROM address_book_collection_rules WHERE collection_id = ?1",
        [id],
    );
    let _ = conn.execute("DELETE FROM address_books WHERE collection_id = ?1", [id]);
    let _ = conn.execute("DELETE FROM address_book_collections WHERE id = ?1", [id]);
    let _ = conn.execute_batch("COMMIT");
    drop(conn);
    common::success(Value::Null)
}

/// GET /api/admin/address_book_collection_rule/list
pub async fn handle_abcr_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AbcrQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    if q.user_id > 0 {
        params.push(Box::new(q.user_id));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    }
    if q.collection_id > 0 {
        params.push(Box::new(q.collection_id));
        wc.push_str(&format!(
            "{} collection_id = ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            params.len()
        ));
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "address_book_collection_rules", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM address_book_collection_rules {} ORDER BY id LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_abcr)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    let list: Vec<Value> = rows.iter().map(abcr_json).collect();
    page_ok(page, total, size, json!(list))
}

/// GET /api/admin/address_book_collection_rule/detail/:id
pub async fn handle_abcr_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let r = conn
        .query_row(
            "SELECT * FROM address_book_collection_rules WHERE id = ?1",
            [iid],
            row_to_abcr,
        )
        .ok();
    drop(conn);
    match r {
        Some(r) if r.id > 0 => common::success(abcr_json(&r)),
        _ => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// abcr 通用 CheckForm（管理员版：UserId 必须 >0；owner 校验；to_id 存在性；重复检查）
fn abcr_check_form(
    conn: &rusqlite::Connection,
    t: &crate::models::AddressBookCollectionRule,
) -> Result<(), &'static str> {
    if t.user_id == 0 {
        return Err("ParamsError");
    }
    if t.collection_id > 0 && !check_collection_owner(conn, t.user_id, t.collection_id) {
        return Err("ParamsError");
    }
    if t.type_ == 1 {
        if t.to_id == t.user_id {
            return Err("CannotShareToSelf");
        }
        let exists: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE id = ?1", [t.to_id], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        if exists == 0 {
            return Err("ItemNotFound");
        }
    } else if t.type_ == 2 {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM groups WHERE id = ?1",
                [t.to_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            return Err("ItemNotFound");
        }
    } else {
        return Err("ParamsError");
    }
    // 重复检查
    let ex_id: i64 = conn
        .query_row(
            "SELECT id FROM address_book_collection_rules WHERE type=?1 AND to_id=?2 AND collection_id=?3 LIMIT 1",
            rusqlite::params![t.type_, t.to_id, t.collection_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if t.id == 0 && ex_id > 0 {
        return Err("ItemExists");
    }
    if t.id > 0 && ex_id > 0 && t.id != ex_id {
        return Err("ItemExists");
    }
    Ok(())
}

fn parse_abcr(b: &Value) -> Option<crate::models::AddressBookCollectionRule> {
    Some(crate::models::AddressBookCollectionRule {
        id: b.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
        user_id: b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0),
        collection_id: b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0),
        rule: b.get("rule").and_then(|v| v.as_i64()).unwrap_or(0),
        type_: b.get("type").and_then(|v| v.as_i64()).unwrap_or(0),
        to_id: b.get("to_id").and_then(|v| v.as_i64()).unwrap_or(0),
        ..Default::default()
    })
}

/// POST /api/admin/address_book_collection_rule/create
pub async fn handle_abcr_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let t = match parse_abcr(&b) {
        Some(t) => t,
        None => return common::fail_h(101, "ParamsError", &headers),
    };
    if t.type_ != 1 && t.type_ != 2 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    if t.rule < 1 || t.rule > 3 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    if let Err(msg) = abcr_check_form(&conn, &t) {
        drop(conn);
        return common::fail_h(101, msg, &headers);
    }
    let res = conn.execute(
        "INSERT INTO address_book_collection_rules (user_id, collection_id, rule, type, to_id, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?6)",
        rusqlite::params![t.user_id, t.collection_id, t.rule, t.type_, t.to_id, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/address_book_collection_rule/update
pub async fn handle_abcr_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let t = match parse_abcr(&b) {
        Some(t) => t,
        None => return common::fail_h(101, "ParamsError", &headers),
    };
    if t.id == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    if t.rule < 1 || t.rule > 3 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collection_rules WHERE id = ?1",
            [t.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    if let Err(msg) = abcr_check_form(&conn, &t) {
        drop(conn);
        return common::fail_h(101, msg, &headers);
    }
    // Updates 非零字段
    let _ = conn.execute(
        "UPDATE address_book_collection_rules SET user_id=?1, collection_id=?2, rule=?3, type=?4, to_id=?5, updated_at=?6 WHERE id=?7",
        rusqlite::params![t.user_id, t.collection_id, t.rule, t.type_, t.to_id, now_sql(), t.id],
    );
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/address_book_collection_rule/delete
pub async fn handle_abcr_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collection_rules WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute(
        "DELETE FROM address_book_collection_rules WHERE id = ?1",
        [id],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

// ─────────────────────────── user_token / share_record ───────────────────────────

fn row_to_user_token(row: &rusqlite::Row) -> rusqlite::Result<crate::models::UserToken> {
    Ok(crate::models::UserToken {
        id: row.get(0)?,
        user_id: row.get(1)?,
        device_uuid: row.get(2)?,
        device_id: row.get(3)?,
        token: row.get(4)?,
        expired_at: row.get(5)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(6)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(7)?),
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct UserTokenQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
}

/// GET /api/admin/user_token/list
pub async fn handle_user_token_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<UserTokenQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let (wc, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if q.user_id > 0 {
        ("WHERE user_id = ?1".into(), vec![Box::new(q.user_id)])
    } else {
        (String::new(), vec![])
    };
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "user_tokens", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM user_tokens {} ORDER BY id DESC LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_user_token)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// POST /api/admin/user_token/delete（非 admin 只能删自己的）
pub async fn handle_user_token_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(u) => u,
        Err(e) => return auth_err(e, &headers),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let owner: i64 = conn
        .query_row("SELECT user_id FROM user_tokens WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if owner == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    if !user.is_admin() && owner != user.id {
        drop(conn);
        return common::fail_h(101, "NoAccess", &headers);
    }
    let res = conn.execute("DELETE FROM user_tokens WHERE id = ?1", [id]);
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// POST /api/admin/user_token/batchDelete
pub async fn handle_user_token_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    batch_delete_ids(&state, &headers, &b, "user_tokens")
}

fn row_to_share_record(row: &rusqlite::Row) -> rusqlite::Result<crate::models::ShareRecord> {
    Ok(crate::models::ShareRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        peer_id: row.get(2)?,
        share_token: row.get(3)?,
        password_type: row.get(4)?,
        password: row.get(5)?,
        expire: row.get(6)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(7)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(8)?),
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct ShareRecordQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub user_id: i64,
}

pub fn share_record_list(
    state: &AdminState,
    q: &ShareRecordQuery,
    force_user_id: Option<i64>,
) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let uid = force_user_id.or(if q.user_id > 0 { Some(q.user_id) } else { None });
    let (wc, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = match uid {
        Some(uid) => ("WHERE user_id = ?1".into(), vec![Box::new(uid)]),
        None => (String::new(), vec![]),
    };
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "share_records", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM share_records {} ORDER BY id LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_share_record)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// GET /api/admin/share_record/list
pub async fn handle_share_record_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<ShareRecordQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    share_record_list(&state, &q, None)
}

/// POST /api/admin/share_record/delete
pub async fn handle_share_record_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    delete_by_ids(&state, &headers, &b, "share_records", "id")
}

/// POST /api/admin/share_record/batchDelete
pub async fn handle_share_record_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    batch_delete_ids(&state, &headers, &b, "share_records")
}

// ══════════════════════════════════════════════════════════════════
// OAuth CRUD（对齐 Go controller/admin/oauth + service/oauth FormatOauthInfo）
// 注意：Go 中 oauth CRUD 在 AdminPrivilege 组，这里 handler 内做 is_admin 校验
// ══════════════════════════════════════════════════════════════════

pub fn row_to_oauth(row: &rusqlite::Row) -> rusqlite::Result<crate::models::Oauth> {
    Ok(crate::models::Oauth {
        id: row.get(0)?,
        op: row.get(1)?,
        oauth_type: row.get(2)?,
        client_id: row.get(3)?,
        client_secret: row.get(4)?,
        auto_register: row.get::<_, i64>(5)? != 0,
        scopes: row.get(6)?,
        issuer: row.get(7)?,
        pkce_enable: row.get::<_, i64>(8)? != 0,
        pkce_method: row.get(9)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(10)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
    })
}

/// FormatOauthInfo：github/google/linuxdo 固定 op；空 op→"oidc"；google 空 issuer→accounts.google.com
fn oauth_json(mut o: crate::models::Oauth) -> Value {
    match o.op.as_str() {
        "github" | "google" | "linuxdo" => {}
        "" => o.op = "oidc".to_string(),
        _ => {}
    }
    if o.op == "google" && o.issuer.is_empty() {
        o.issuer = "https://accounts.google.com".to_string();
    }
    json!({
        "id": o.id, "op": o.op, "oauthType": o.oauth_type,
        "clientId": o.client_id, "clientSecret": o.client_secret,
        "autoRegister": o.auto_register, "scopes": o.scopes,
        "issuer": o.issuer, "pkceEnable": o.pkce_enable,
        "pkceMethod": if o.pkce_method.is_empty() { "S256".to_string() } else { o.pkce_method.clone() },
        "createdAt": o.created_at, "updatedAt": o.updated_at,
    })
}

fn oauth_by_id(conn: &rusqlite::Connection, id: i64) -> Option<crate::models::Oauth> {
    conn.query_row(
        "SELECT id, op, oauth_type, client_id, client_secret, auto_register, scopes, issuer, pkce_enable, pkce_method, created_at, updated_at FROM oauths WHERE id = ?1",
        [id], row_to_oauth,
    ).ok()
}

fn oauth_by_op(conn: &rusqlite::Connection, op: &str) -> Option<crate::models::Oauth> {
    conn.query_row(
        "SELECT id, op, oauth_type, client_id, client_secret, auto_register, scopes, issuer, pkce_enable, pkce_method, created_at, updated_at FROM oauths WHERE op = ?1",
        [op], row_to_oauth,
    ).ok()
}

fn parse_oauth_body(b: &Value) -> Result<crate::models::Oauth, (i64, &'static str)> {
    let op = b
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if op.is_empty() {
        return Err((400, "op required"));
    }
    let oauth_type = b
        .get("oauthType")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if oauth_type.is_empty() {
        return Err((400, "oauthType required"));
    }
    let client_id = b
        .get("clientId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let client_secret = b
        .get("clientSecret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut issuer = b
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if oauth_type == "oidc" && issuer.is_empty() {
        return Err((400, "issuer required"));
    }
    if op == "google" && issuer.is_empty() {
        issuer = "https://accounts.google.com".to_string();
    }
    Ok(crate::models::Oauth {
        id: 0,
        op,
        oauth_type,
        client_id,
        client_secret,
        auto_register: b
            .get("autoRegister")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        scopes: b
            .get("scopes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        issuer,
        pkce_enable: b
            .get("pkceEnable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        pkce_method: b
            .get("pkceMethod")
            .and_then(|v| v.as_str())
            .unwrap_or("S256")
            .to_string(),
        created_at: String::new(),
        updated_at: String::new(),
    })
}

/// GET /api/admin/oauth/list
pub async fn handle_oauth_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let (page, size) = page_args(&q);
    let conn = state.db.conn();
    let total = count(&conn, "oauths", "", &[]);
    let offset = (page - 1) * size;
    let mut stmt = conn
        .prepare("SELECT id, op, oauth_type, client_id, client_secret, auto_register, scopes, issuer, pkce_enable, pkce_method, created_at, updated_at FROM oauths ORDER BY id LIMIT ?1 OFFSET ?2")
        .unwrap();
    let rows: Vec<Value> = stmt
        .query_map([offset, size], row_to_oauth)
        .unwrap()
        .filter_map(|r| r.ok())
        .map(oauth_json)
        .collect();
    drop(stmt);
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

#[derive(Debug, Deserialize, Default)]
pub struct IdQuery {
    #[serde(default)]
    pub id: i64,
}

/// GET /api/admin/oauth/detail/:id
pub async fn handle_oauth_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    match oauth_by_id(&conn, iid) {
        Some(o) => {
            drop(conn);
            common::success(oauth_json(o))
        }
        None => {
            drop(conn);
            common::fail_h(400, "ItemNotFound", &headers)
        }
    }
}

/// POST /api/admin/oauth/create
pub async fn handle_oauth_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let o = match parse_oauth_body(&b) {
        Ok(o) => o,
        Err((code, msg)) => return common::fail_h(code, msg, &headers),
    };
    let now = now_sql();
    let conn = state.db.conn();
    if oauth_by_op(&conn, &o.op).is_some() {
        drop(conn);
        return common::fail_h(400, "ItemExists", &headers);
    }
    let res = conn.execute(
        "INSERT INTO oauths (op, oauth_type, client_id, client_secret, auto_register, scopes, issuer, pkce_enable, pkce_method, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
        rusqlite::params![o.op, o.oauth_type, o.client_id, o.client_secret, o.auto_register as i64, o.scopes, o.issuer, o.pkce_enable as i64, o.pkce_method, now],
    );
    match res {
        Ok(_) => {
            let id = conn.last_insert_rowid();
            let o2 = oauth_by_id(&conn, id);
            drop(conn);
            match o2 {
                Some(x) => common::success(oauth_json(x)),
                None => common::fail_h(400, "OperationFailed", &headers),
            }
        }
        Err(_) => {
            drop(conn);
            common::fail_h(400, "OperationFailed", &headers)
        }
    }
}

/// POST /api/admin/oauth/update
pub async fn handle_oauth_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let conn = state.db.conn();
    let old = match oauth_by_id(&conn, id) {
        Some(o) => o,
        None => {
            drop(conn);
            return common::fail_h(400, "ItemNotFound", &headers);
        }
    };
    let o = match parse_oauth_body(&b) {
        Ok(o) => o,
        Err((code, msg)) => {
            drop(conn);
            return common::fail_h(code, msg, &headers);
        }
    };
    // op 与其他记录冲突检查
    if o.op != old.op {
        if let Some(ex) = oauth_by_op(&conn, &o.op) {
            if ex.id != id {
                drop(conn);
                return common::fail_h(400, "ItemExists", &headers);
            }
        }
    }
    let now = now_sql();
    let res = conn.execute(
        "UPDATE oauths SET op=?1, oauth_type=?2, client_id=?3, client_secret=?4, auto_register=?5, scopes=?6, issuer=?7, pkce_enable=?8, pkce_method=?9, updated_at=?10 WHERE id=?11",
        rusqlite::params![o.op, o.oauth_type, o.client_id, o.client_secret, o.auto_register as i64, o.scopes, o.issuer, o.pkce_enable as i64, o.pkce_method, now, id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(json!({})),
        Err(_) => common::fail_h(400, "OperationFailed", &headers),
    }
}

/// POST /api/admin/oauth/delete
pub async fn handle_oauth_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    delete_by_ids(&state, &headers, &b, "oauths", "id")
}

// ══════════════════════════════════════════════════════════════════
// RustDesk 系统命令（对齐 Go service/serverCmd + controller/admin/rustdesk）
// 仅需登录（auth_user），无 AdminPrivilege
// ══════════════════════════════════════════════════════════════════

fn row_to_server_cmd(row: &rusqlite::Row) -> rusqlite::Result<crate::models::ServerCmd> {
    Ok(crate::models::ServerCmd {
        id: row.get(0)?,
        cmd: row.get(1)?,
        alias: row.get(2)?,
        option: row.get(3)?,
        explain: row.get(4)?,
        target: row.get(5)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(6)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(7)?),
    })
}

fn server_cmd_json(c: crate::models::ServerCmd) -> Value {
    json!({
        "id": c.id, "cmd": c.cmd, "alias": c.alias, "option": c.option,
        "explain": c.explain, "target": c.target,
        "createdAt": c.created_at, "updatedAt": c.updated_at,
    })
}

/// 系统内置命令（对齐 Go service/serverCmd.go SysIdServerCmds / SysRelayServerCmds）
fn sys_id_server_cmds() -> Vec<crate::models::ServerCmd> {
    let n = "ID Server";
    let mk = |cmd: &str, alias: &str, option: &str, explain: &str| crate::models::ServerCmd {
        id: 0,
        cmd: cmd.to_string(),
        alias: alias.to_string(),
        option: option.to_string(),
        explain: explain.to_string(),
        target: "21115".to_string(),
        created_at: String::new(),
        updated_at: String::new(),
    };
    vec![
        mk("h", "help", "", &format!("{}: show help", n)),
        mk("rs", "restart", "", &format!("{}: restart server", n)),
        mk(
            "ib",
            "install-boot",
            "",
            &format!("{}: install boot service", n),
        ),
        mk(
            "ic",
            "install-config",
            "",
            &format!("{}: install config", n),
        ),
        mk(
            "aur",
            "auto-update-rate",
            "123",
            &format!("{}: auto update rate", n),
        ),
        mk("tg", "token-gen", "", &format!("{}: generate token", n)),
    ]
}

fn sys_relay_server_cmds() -> Vec<crate::models::ServerCmd> {
    let n = "Relay Server";
    let mk = |cmd: &str, alias: &str, option: &str, explain: &str| crate::models::ServerCmd {
        id: 0,
        cmd: cmd.to_string(),
        alias: alias.to_string(),
        option: option.to_string(),
        explain: explain.to_string(),
        target: "21117".to_string(),
        created_at: String::new(),
        updated_at: String::new(),
    };
    vec![
        mk("h", "help", "", &format!("{}: show help", n)),
        mk("ba", "batch-add", "new", &format!("{}: batch add", n)),
        mk("br", "batch-remove", "old", &format!("{}: batch remove", n)),
        mk("b", "batch", "", &format!("{}: batch", n)),
        mk("Ba", "Batch-add", "", &format!("{}: Batch add", n)),
        mk("Br", "Batch-remove", "", &format!("{}: Batch remove", n)),
        mk("B", "Batch", "", &format!("{}: Batch", n)),
        mk("dt", "dynamic-ttl", "", &format!("{}: dynamic ttl", n)),
        mk("t", "ttl", "", &format!("{}: ttl", n)),
        mk("ls", "list", "", &format!("{}: list", n)),
        mk("tb", "transfer-back", "", &format!("{}: transfer back", n)),
        mk(
            "sb",
            "synchronize-back",
            "",
            &format!("{}: synchronize back", n),
        ),
        mk("u", "update", "", &format!("{}: update", n)),
    ]
}

/// GET /api/admin/rustdesk/cmdList —— 系统命令排在 DB 记录之前
pub async fn handle_rustdesk_cmd_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    let (page, size) = page_args(&q);
    let conn = state.db.conn();
    let total = count(&conn, "server_cmds", "", &[]);
    let offset = (page - 1) * size;
    let mut stmt = conn
        .prepare("SELECT id, cmd, alias, option, explain, target, created_at, updated_at FROM server_cmds ORDER BY id LIMIT ?1 OFFSET ?2")
        .unwrap();
    let mut rows: Vec<crate::models::ServerCmd> = stmt
        .query_map([offset, size], row_to_server_cmd)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    drop(conn);
    let mut list: Vec<Value> = sys_id_server_cmds()
        .into_iter()
        .chain(sys_relay_server_cmds())
        .map(server_cmd_json)
        .collect();
    list.extend(rows.drain(..).map(server_cmd_json));
    page_ok(page, total, size, json!(list))
}

/// POST /api/admin/rustdesk/cmdCreate
pub async fn handle_rustdesk_cmd_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    let cmd = b
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if cmd.is_empty() {
        return common::fail(400, "cmd required");
    }
    let target = b
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if target != "21115" && target != "21117" {
        return common::fail(400, "target must be 21115 or 21117");
    }
    let alias = b
        .get("alias")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let option = b
        .get("option")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let explain = b
        .get("explain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = now_sql();
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO server_cmds (cmd, alias, option, explain, target, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
        rusqlite::params![cmd, alias, option, explain, target, now],
    );
    match res {
        Ok(_) => {
            let id = conn.last_insert_rowid();
            let c = conn.query_row(
                "SELECT id, cmd, alias, option, explain, target, created_at, updated_at FROM server_cmds WHERE id=?1",
                [id], row_to_server_cmd,
            );
            drop(conn);
            match c {
                Ok(c) => common::success(server_cmd_json(c)),
                Err(_) => common::fail_h(400, "OperationFailed", &headers),
            }
        }
        Err(_) => {
            drop(conn);
            common::fail_h(400, "OperationFailed", &headers)
        }
    }
}

/// POST /api/admin/rustdesk/cmdDelete
pub async fn handle_rustdesk_cmd_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    delete_by_ids(&state, &headers, &b, "server_cmds", "id")
}

/// POST /api/admin/rustdesk/sendCmd —— TCP 发到 hbbs(21115→id_port-1)/hbbr(21117→relay_port)
pub async fn handle_rustdesk_send_cmd(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    let cmd = b
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if cmd.is_empty() {
        return common::fail(400, "cmd required");
    }
    let target = b
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if target != "21115" && target != "21117" {
        return common::fail(400, "target must be 21115 or 21117");
    }
    let option = b
        .get("option")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 读端口配置
    let cfg = state.config_manager.get().await;
    let port: u16 = if target == "21115" {
        cfg.admin.id_server_port.saturating_sub(1)
    } else {
        cfg.admin.relay_server_port
    };
    drop(cfg);

    let msg = if option.is_empty() {
        cmd.clone()
    } else {
        format!("{} {}", cmd, option)
    };

    // 对齐 Go：先尝试 tcp6 [::1]，再 tcp 127.0.0.1
    let addrs: [(&str, u16); 2] = [("::1", port), ("127.0.0.1", port)];
    let mut last_err = String::new();
    let mut response = String::new();
    let mut sent = false;
    for (host, p) in addrs {
        let sa: std::net::SocketAddr = match format!("{}:{}", host, p).parse() {
            Ok(sa) => sa,
            Err(_) => continue,
        };
        match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(3)) {
            Ok(mut stream) => {
                use std::io::{Read, Write};
                if stream.write_all(msg.as_bytes()).is_ok() {
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf) {
                        response = String::from_utf8_lossy(&buf[..n]).to_string();
                    }
                }
                sent = true;
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    if sent {
        common::success(json!({ "result": response }))
    } else {
        common::fail_msg(400, format!("connect failed: {}", last_err))
    }
}

// ══════════════════════════════════════════════════════════════════
// Dashboard 统计（对齐 Go service/dashboard.go + controller/admin/dashboard）
// 仅需登录
// ══════════════════════════════════════════════════════════════════

fn os_short(os: &str) -> &'static str {
    let l = os.to_lowercase();
    if l.contains("windows") {
        "Windows"
    } else if l.contains("mac") || l.contains("darwin") {
        "Mac OS"
    } else if l.contains("linux") {
        "Linux"
    } else {
        "Other"
    }
}

/// GET /api/admin/dashboard/stats
pub async fn handle_dashboard_stats(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    let conn = state.db.conn();
    let now = chrono::Utc::now();
    let today = now.format("%Y-%m-%d 00:00:00").to_string();

    let total_peers: i64 = conn
        .query_row("SELECT COUNT(*) FROM peers", [], |r| r.get(0))
        .unwrap_or(0);
    let now_ts = crate::db::now_unix();
    let online_24h: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM peers WHERE last_online_time > ?1",
            [now_ts - 86400],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let offline_peers = (total_peers - online_24h).max(0);
    let total_users: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(0);
    let today_conns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_conns WHERE action='new' AND created_at >= ?1",
            [&today],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let today_closed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_conns WHERE action='close' AND created_at >= ?1 AND close_time > 0",
            [&today],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let active_conns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_conns WHERE close_time = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    // trend：最近 7 天连接数（按 action=new 且 created_at 在当天），缺失补 0
    let mut trend = Vec::new();
    for i in (0..7).rev() {
        let day_start = now - chrono::Duration::days(i);
        let start = day_start.format("%Y-%m-%d 00:00:00").to_string();
        let end = (day_start + chrono::Duration::days(1))
            .format("%Y-%m-%d 00:00:00")
            .to_string();
        let c: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_conns WHERE action='new' AND created_at >= ?1 AND created_at < ?2",
                [&start, &end],
                |r| r.get(0),
            )
            .unwrap_or(0);
        trend.push(json!({
            "date": day_start.format("%Y-%m-%d").to_string(),
            "count": c,
        }));
    }

    // os_dist：按 osShort 归类，count>0 才输出，固定顺序 windows/macos/linux/other
    let mut stmt = match conn.prepare("SELECT os FROM peers") {
        Ok(s) => s,
        Err(_) => {
            return common::fail_h(400, "OperationFailed", &headers);
        }
    };
    let mut dist: std::collections::HashMap<&'static str, i64> = std::collections::HashMap::new();
    if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
        for os in rows.filter_map(|x| x.ok()) {
            let key = match os_short(&os) {
                "Windows" => "windows",
                "Mac OS" => "macos",
                "Linux" => "linux",
                _ => "other",
            };
            *dist.entry(key).or_insert(0) += 1;
        }
    }
    drop(stmt);
    let mut os_dist = Vec::new();
    for key in ["windows", "macos", "linux", "other"] {
        if let Some(c) = dist.get(key) {
            if *c > 0 {
                let name = match key {
                    "windows" => "Windows",
                    "macos" => "Mac OS",
                    "linux" => "Linux",
                    _ => "Other",
                };
                os_dist.push(json!({ "name": name, "count": c }));
            }
        }
    }

    // recent_peers：最近在线 Top8
    let mut stmt = match conn.prepare(
        "SELECT id, cpu, hostname, memory, os, username, uuid, version, user_id, last_online_time, last_online_ip, group_id, alias, created_at, updated_at FROM peers ORDER BY last_online_time DESC LIMIT 8",
    ) {
        Ok(s) => s,
        Err(_) => {
            return common::fail_h(400, "OperationFailed", &headers);
        }
    };
    let recent_peers: Vec<Value> = stmt
        .query_map([], |row| {
            let p = row_to_peer_full(row)?;
            Ok(json!({
                "id": p.id, "hostname": p.hostname, "os": p.os, "alias": p.alias,
                "lastOnlineTime": p.last_online_time,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);

    // recent_conns：最近连接 Top8（id 倒序）
    let mut stmt = match conn.prepare(
        "SELECT id, action, conn_id, peer_id, from_peer, from_name, ip, session_id, type, uuid, close_time, created_at, updated_at FROM audit_conns ORDER BY id DESC LIMIT 8",
    ) {
        Ok(s) => s,
        Err(_) => {
            return common::fail_h(400, "OperationFailed", &headers);
        }
    };
    let recent_conns: Vec<Value> = stmt
        .query_map([], |row| {
            let ac = row_to_audit_conn(row)?;
            Ok(json!({
                "id": ac.id, "peerId": ac.peer_id, "fromName": ac.from_name,
                "ip": ac.ip, "action": ac.action,
                "createdAt": ac.created_at,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    drop(conn);

    common::success(json!({
        "totalPeers": total_peers,
        "onlinePeers": online_24h,
        "offlinePeers": offline_peers,
        "totalUsers": total_users,
        "todayConns": today_conns,
        "todayClosedConns": today_closed,
        "activeConns": active_conns,
        "trend": trend,
        "osDistribution": os_dist,
        "recentPeers": recent_peers,
        "recentConns": recent_conns,
    }))
}

// ══════════════════════════════════════════════════════════════════
// Peer CRUD（对齐 Go controller/admin/peer + service/peer）
// admin 组；simpleData 仅需登录
// ══════════════════════════════════════════════════════════════════

fn peer_cols() -> &'static str {
    "row_id, id, cpu, hostname, memory, os, username, uuid, version, user_id, last_online_time, last_online_ip, group_id, alias, created_at, updated_at"
}

fn row_to_peer_full(row: &rusqlite::Row) -> rusqlite::Result<crate::models::Peer> {
    Ok(crate::models::Peer {
        row_id: row.get(0)?,
        id: row.get(1)?,
        cpu: row.get(2)?,
        hostname: row.get(3)?,
        memory: row.get(4)?,
        os: row.get(5)?,
        username: row.get(6)?,
        uuid: row.get(7)?,
        version: row.get(8)?,
        user_id: row.get(9)?,
        last_online_time: row.get(10)?,
        last_online_ip: row.get(11)?,
        group_id: row.get(12)?,
        alias: row.get(13)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(14)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(15)?),
    })
}

fn peer_json(p: &crate::models::Peer) -> Value {
    // 注意：SELECT * 的列序 = row_id, id, cpu, hostname, memory, os, username, uuid, version, user_id, last_online_time, last_online_ip, group_id, alias, created_at, updated_at
    // 见 db_schema.sql peers 表定义
    json!({
        "row_id": p.row_id, "id": p.id, "cpu": p.cpu, "hostname": p.hostname,
        "memory": p.memory, "os": p.os, "username": p.username, "uuid": p.uuid,
        "version": p.version, "user_id": p.user_id,
        "last_online_time": p.last_online_time, "last_online_ip": p.last_online_ip,
        "group_id": p.group_id, "alias": p.alias,
        "created_at": p.created_at, "updated_at": p.updated_at,
    })
}

#[derive(Debug, Deserialize, Default)]
pub struct PeerQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user_id: i64,
    /// >0 → last_online_time < now-ago；<0 → > now+|ago|（对齐 Go TimeAgo）
    #[serde(default)]
    pub time_ago: i64,
}

pub fn peer_list(state: &AdminState, q: &PeerQuery, force_user_id: Option<i64>) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    let add = |wc: &mut String,
               params: &mut Vec<Box<dyn rusqlite::ToSql>>,
               cond: &str,
               val: Box<dyn rusqlite::ToSql>| {
        wc.push_str(&format!(
            "{} {} ?{}",
            if wc.is_empty() { " WHERE" } else { " AND" },
            cond,
            params.len() + 1
        ));
        params.push(val);
    };
    if let Some(uid) = force_user_id {
        add(&mut wc, &mut params, "user_id =", Box::new(uid));
    } else if q.user_id > 0 {
        add(&mut wc, &mut params, "user_id =", Box::new(q.user_id));
    }
    if !q.id.is_empty() {
        add(&mut wc, &mut params, "id LIKE", Box::new(like(&q.id)));
    }
    if !q.username.is_empty() {
        add(
            &mut wc,
            &mut params,
            "username LIKE",
            Box::new(like(&q.username)),
        );
    }
    if !q.hostname.is_empty() {
        add(
            &mut wc,
            &mut params,
            "hostname LIKE",
            Box::new(like(&q.hostname)),
        );
    }
    if q.time_ago > 0 {
        let cut = crate::db::now_unix() - q.time_ago;
        add(&mut wc, &mut params, "last_online_time <", Box::new(cut));
    } else if q.time_ago < 0 {
        let cut = crate::db::now_unix() + q.time_ago.abs();
        add(&mut wc, &mut params, "last_online_time >", Box::new(cut));
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "peers", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT {} FROM peers {} ORDER BY row_id LIMIT {} OFFSET {}",
            peer_cols(),
            wc,
            size,
            offset
        ))
        .ok()
        .and_then(|mut stmt| {
            let it = match stmt.query_map(p.as_slice(), row_to_peer_full) {
                Ok(it) => it,
                Err(e) => {
                    tracing::error!("peer_list query_map: {}", e);
                    return None;
                }
            };
            match it.collect::<Result<Vec<_>, _>>() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::error!("peer_list row parse: {}", e);
                    None
                }
            }
        })
        .unwrap_or_default();
    drop(conn);
    let list: Vec<Value> = rows.iter().map(peer_json).collect();
    page_ok(page, total, size, json!(list))
}

/// GET /api/admin/peer/list
pub async fn handle_peer_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PeerQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    peer_list(&state, &q, None)
}

/// GET /api/admin/peer/detail/:id
pub async fn handle_peer_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let iid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let row = conn
        .query_row(
            &format!("SELECT {} FROM peers WHERE row_id = ?1", peer_cols()),
            [iid],
            row_to_peer_full,
        )
        .ok();
    drop(conn);
    match row {
        Some(p) => common::success(peer_json(&p)),
        None => common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/peer/create
pub async fn handle_peer_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let pid = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if pid.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM peers WHERE id = ?1", [&pid], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists > 0 {
        drop(conn);
        return common::fail_h(101, "ItemExists", &headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "INSERT INTO peers (id, cpu, hostname, memory, os, username, uuid, version, user_id, last_online_time, last_online_ip, group_id, alias, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)",
        rusqlite::params![
            pid,
            b.get("cpu").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("memory").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("os").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("username").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("uuid").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("version").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("last_online_time").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("last_online_ip").and_then(|v| v.as_str()).unwrap_or(""),
            b.get("group_id").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
            now,
        ],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/peer/update（GORM Updates 非零字段语义）
pub async fn handle_peer_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let rid = b
        .get("row_id")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            b.get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok())
        })
        .unwrap_or(0);
    if rid == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM peers WHERE row_id = ?1", [rid], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let mut sets: Vec<String> = vec![];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    let add_field = |sets: &mut Vec<String>,
                     params: &mut Vec<Box<dyn rusqlite::ToSql>>,
                     col: &str,
                     val: Box<dyn rusqlite::ToSql>| {
        sets.push(format!("{} = ?{}", col, params.len() + 1));
        params.push(val);
    };
    if let Some(v) = b.get("cpu").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "cpu", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("hostname").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "hostname", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("memory").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "memory", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("os").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "os", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("username").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "username", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("uuid").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "uuid", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("version").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "version", Box::new(v.to_string()));
        }
    }
    if let Some(v) = b.get("user_id").and_then(|v| v.as_i64()) {
        if v != 0 {
            add_field(&mut sets, &mut params, "user_id", Box::new(v));
        }
    }
    if let Some(v) = b.get("last_online_time").and_then(|v| v.as_i64()) {
        if v != 0 {
            add_field(&mut sets, &mut params, "last_online_time", Box::new(v));
        }
    }
    if let Some(v) = b.get("last_online_ip").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(
                &mut sets,
                &mut params,
                "last_online_ip",
                Box::new(v.to_string()),
            );
        }
    }
    if let Some(v) = b.get("group_id").and_then(|v| v.as_i64()) {
        if v != 0 {
            add_field(&mut sets, &mut params, "group_id", Box::new(v));
        }
    }
    if let Some(v) = b.get("alias").and_then(|v| v.as_str()) {
        if !v.is_empty() {
            add_field(&mut sets, &mut params, "alias", Box::new(v.to_string()));
        }
    }
    if sets.is_empty() {
        drop(conn);
        return common::success(Value::Null);
    }
    sets.push(format!("updated_at = ?{}", params.len() + 1));
    params.push(Box::new(now_sql()));
    let sql = format!(
        "UPDATE peers SET {} WHERE row_id = ?{}",
        sets.join(", "),
        params.len() + 1
    );
    // row_id 是最后一个参数，追加
    let mut all: Vec<Box<dyn rusqlite::ToSql>> = params;
    all.push(Box::new(rid));
    let pa: Vec<&dyn rusqlite::ToSql> = all.iter().map(|x| x.as_ref()).collect();
    let res = conn.execute(&sql, pa.as_slice());
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

fn flush_token_by_uuids(conn: &rusqlite::Connection, uuids: &[String]) {
    for u in uuids {
        let _ = conn.execute("DELETE FROM user_tokens WHERE device_uuid = ?1", [u]);
    }
}

/// POST /api/admin/peer/delete
pub async fn handle_peer_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let rid = b
        .get("row_id")
        .and_then(|v| v.as_i64())
        .or_else(|| b.get("id").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    if rid == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let uuid: Option<String> = conn
        .query_row("SELECT uuid FROM peers WHERE row_id = ?1", [rid], |r| {
            r.get(0)
        })
        .ok();
    let exists: i64 = conn
        .query_row("SELECT COUNT(*) FROM peers WHERE row_id = ?1", [rid], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let res = conn.execute("DELETE FROM peers WHERE row_id = ?1", [rid]);
    if res.is_ok() {
        if let Some(u) = uuid {
            flush_token_by_uuids(&conn, &[u]);
        }
    }
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/peer/batchDelete
pub async fn handle_peer_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let params: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|i| i as &dyn rusqlite::ToSql).collect();
    let uuids: Vec<String> = conn
        .prepare(&format!(
            "SELECT uuid FROM peers WHERE row_id IN ({})",
            placeholders
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(params.as_slice(), |r| r.get::<_, String>(0))
                .ok()
                .map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    let res = conn.execute(
        &format!("DELETE FROM peers WHERE row_id IN ({})", placeholders),
        params.as_slice(),
    );
    if res.is_ok() {
        flush_token_by_uuids(&conn, &uuids);
    }
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// GET /api/admin/peer/simpleData —— 仅需登录；只取 id + version
pub async fn handle_peer_simple_data(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<PeerQuery>,
) -> Json<Value> {
    if auth_user(&state, &headers).await.is_err() {
        return common::fail_h(403, "NeedLogin", &headers);
    }
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let total = count(&conn, "peers", "", &[]);
    let offset = (page - 1) * size;
    let rows: Vec<Value> = conn
        .prepare("SELECT id, version FROM peers ORDER BY row_id LIMIT ?1 OFFSET ?2")
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([offset, size], |r| {
                Ok(json!({ "id": r.get::<_, String>(0)?, "version": r.get::<_, String>(1)? }))
            })
            .ok()
            .map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

// ══════════════════════════════════════════════════════════════════
// Address_book handlers（对齐 Go controller/admin/addressBook）
// ══════════════════════════════════════════════════════════════════

/// GET /api/admin/address_book/list
pub async fn handle_address_book_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AddressBookQuery>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    ab_list(&state, &q, None)
}

fn address_book_by_id(conn: &rusqlite::Connection, rid: i64) -> Option<crate::models::AddressBook> {
    conn.query_row(
        "SELECT * FROM address_books WHERE row_id = ?1",
        [rid],
        row_to_address_book,
    )
    .ok()
}

/// GET /api/admin/address_book/detail/:id
pub async fn handle_address_book_detail(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let rid: i64 = id.parse().unwrap_or(0);
    let conn = state.db.conn();
    let ab = address_book_by_id(&conn, rid);
    drop(conn);
    match ab {
        Some(ab) => {
            load_collection_cache(&state.db.conn(), &[ab.collection_id]);
            common::success(ab_json(&ab))
        }
        None => common::fail_h(101, "ItemNotFound", &headers),
    }
}

fn parse_address_book_body(
    b: &Value,
    require_id: bool,
) -> Result<crate::models::AddressBook, (i64, &'static str)> {
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if require_id && id.is_empty() {
        return Err((101, "ParamsError"));
    }
    let user_id = b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if user_id == 0 {
        return Err((101, "ParamsError"));
    }
    let collection_id = b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if collection_id < 0 {
        return Err((101, "ParamsError"));
    }
    Ok(crate::models::AddressBook {
        row_id: 0,
        id,
        username: b
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        password: b
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        hostname: b
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        alias: b
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        platform: b
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tags: tags_to_json(b.get("tags")),
        hash: b
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        user_id,
        force_always_relay: b
            .get("forceAlwaysRelay")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        rdp_port: b
            .get("rdpPort")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        rdp_username: b
            .get("rdpUsername")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        online: b.get("online").and_then(|v| v.as_bool()).unwrap_or(false),
        login_name: b
            .get("loginName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        same_server: b
            .get("sameServer")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        collection_id,
        created_at: String::new(),
        updated_at: String::new(),
    })
}

/// POST /api/admin/address_book/create
pub async fn handle_address_book_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let ab = match parse_address_book_body(&b, true) {
        Ok(x) => x,
        Err((c, m)) => return common::fail_h(c, m, &headers),
    };
    // collection owner 校验（cid>0 时）
    let conn = state.db.conn();
    if ab.collection_id > 0 && !check_collection_owner(&conn, ab.user_id, ab.collection_id) {
        drop(conn);
        return common::fail_h(101, "ParamsError", &headers);
    }
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![ab.id, ab.user_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists > 0 {
        drop(conn);
        return common::fail_h(101, "ItemExists", &headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
        rusqlite::params![
            ab.id, ab.username, ab.password, ab.hostname, ab.alias, ab.platform,
            ab.tags, ab.hash, ab.user_id, ab.force_always_relay as i64,
            ab.rdp_port, ab.rdp_username, ab.online as i64, ab.login_name,
            ab.same_server as i64, ab.collection_id, now,
        ],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/address_book/update（Select("*") 全字段更新）
pub async fn handle_address_book_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let rid = b.get("row_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if rid == 0 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let ab = match parse_address_book_body(&b, true) {
        Ok(x) => x,
        Err((c, m)) => return common::fail_h(c, m, &headers),
    };
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE row_id = ?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    if ab.collection_id > 0 && !check_collection_owner(&conn, ab.user_id, ab.collection_id) {
        drop(conn);
        return common::fail_h(101, "ParamsError", &headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "UPDATE address_books SET id=?1, username=?2, password=?3, hostname=?4, alias=?5, platform=?6, tags=?7, hash=?8, user_id=?9, force_always_relay=?10, rdp_port=?11, rdp_username=?12, online=?13, login_name=?14, same_server=?15, collection_id=?16, updated_at=?17 WHERE row_id=?18",
        rusqlite::params![
            ab.id, ab.username, ab.password, ab.hostname, ab.alias, ab.platform,
            ab.tags, ab.hash, ab.user_id, ab.force_always_relay as i64,
            ab.rdp_port, ab.rdp_username, ab.online as i64, ab.login_name,
            ab.same_server as i64, ab.collection_id, now, rid,
        ],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/address_book/delete
pub async fn handle_address_book_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    delete_by_ids_ab(&state, &headers, &b)
}

/// address_book 的单删（主键 row_id；body 传 id=数字字符串或 row_id）
fn delete_by_ids_ab(state: &AdminState, headers: &axum::http::HeaderMap, b: &Value) -> Json<Value> {
    let rid = b
        .get("row_id")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            b.get("id").and_then(|v| v.as_i64()).or_else(|| {
                b.get("id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
            })
        })
        .unwrap_or(0);
    if rid == 0 {
        return common::fail_h(101, "ParamsError", headers);
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE row_id = ?1",
            [rid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", headers);
    }
    let res = conn.execute("DELETE FROM address_books WHERE row_id = ?1", [rid]);
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/address_book/batchCreate —— body: {user_ids:[], address_books:[]} / Go BatchCreate
pub async fn handle_address_book_batch_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let user_ids: Vec<i64> = b
        .get("user_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if user_ids.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let abs: Vec<Value> = b
        .get("address_books")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let conn = state.db.conn();
    let now = now_sql();
    let multi = user_ids.len() > 1;
    for uid in &user_ids {
        for ab in &abs {
            let id = ab.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
                    rusqlite::params![id, uid],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if exists > 0 {
                continue;
            }
            let tags = if multi {
                "[]".to_string()
            } else {
                tags_to_json(ab.get("tags"))
            };
            let cid = if multi {
                0
            } else {
                ab.get("collection_id")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
            };
            let _ = conn.execute(
                "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
                rusqlite::params![
                    id,
                    ab.get("username").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("platform").and_then(|v| v.as_str()).unwrap_or(""),
                    tags,
                    ab.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
                    uid,
                    ab.get("forceAlwaysRelay").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
                    ab.get("rdpPort").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("rdpUsername").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("online").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
                    ab.get("loginName").and_then(|v| v.as_str()).unwrap_or(""),
                    ab.get("sameServer").and_then(|v| v.as_bool()).unwrap_or(false) as i64,
                    cid,
                    now,
                ],
            );
        }
    }
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/address_book/batchCreateFromPeers
pub async fn handle_address_book_batch_create_from_peers(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    if auth_admin(&state, &headers).await.is_err() {
        return common::fail_h(403, "NoAccess", &headers);
    }
    let user_ids: Vec<i64> = b
        .get("user_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    let peer_ids: Vec<String> = b
        .get("peer_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if user_ids.is_empty() || peer_ids.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    let conn = state.db.conn();
    let now = now_sql();
    for uid in &user_ids {
        for pid in &peer_ids {
            let peer = conn.query_row(
                &format!("SELECT {} FROM peers WHERE id = ?1", peer_cols()),
                [pid],
                row_to_peer_full,
            );
            let p = match peer {
                Ok(p) => p,
                Err(_) => continue, // FromPeer 不存在则跳过
            };
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
                    rusqlite::params![pid, uid],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if exists > 0 {
                continue;
            }
            let _ = conn.execute(
                "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,'','',?2,'',?3,'[]','',?4,0,'','',0,'',0,0,?5,?5)",
                rusqlite::params![p.id, p.hostname, platform_from_os(&p.os), uid, now],
            );
        }
    }
    drop(conn);
    common::success(Value::Null)
}

/// POST /api/admin/address_book/shareByWebClient —— 仅需登录（Web Client 分享）
pub async fn handle_address_book_share_by_webclient(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e, &headers),
    };
    let id = b
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password_type = b
        .get("password_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password = b
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let expire = b.get("expire").and_then(|v| v.as_i64()).unwrap_or(0);
    if id.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    if password_type != "once" && password_type != "fixed" {
        return common::fail_h(101, "ParamsError", &headers);
    }
    if password.is_empty() {
        return common::fail_h(101, "ParamsError", &headers);
    }
    // 目标 address_book 必须存在且属于当前用户
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail_h(101, "ItemNotFound", &headers);
    }
    let token = uuid::Uuid::new_v4().to_string();
    let now = now_sql();
    let res = conn.execute(
        "INSERT INTO share_records (user_id, peer_id, share_token, password_type, password, expire, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
        rusqlite::params![user.id, id, token, password_type, password, expire, now],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(json!({ "share_token": token })),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// PlatformFromOs 公开版（client.rs 复用）
pub fn platform_from_os_str(os: &str) -> String {
    platform_from_os(os)
}

/// PlatformFromOs（对齐 Go service/addressBook.go PlatformFromOs）
fn platform_from_os(os: &str) -> String {
    let l = os.to_lowercase();
    if l.contains("android") {
        "Android".to_string()
    } else if l.contains("windows") {
        "Windows".to_string()
    } else if l.contains("linux") {
        "Linux".to_string()
    } else if l.contains("mac") {
        "Mac OS".to_string()
    } else {
        String::new()
    }
}

// ══════════════════════════════════════════════════════════════════
// my.* 复用的 body 版本（auth 已在 my.rs 层完成）
// ══════════════════════════════════════════════════════════════════

/// tag list（可强制 user_id）
pub fn tag_list(state: &AdminState, q: &TagQuery, force_user_id: Option<i64>) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let mut wc = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    let uid = force_user_id.unwrap_or(0);
    if uid > 0 {
        params.push(Box::new(uid));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    } else if q.user_id > 0 {
        params.push(Box::new(q.user_id));
        wc.push_str(&format!(" WHERE user_id = ?{}", params.len()));
    }
    if let Some(cid) = q.collection_id {
        if cid >= 0 {
            params.push(Box::new(cid));
            if wc.is_empty() {
                wc.push_str(" WHERE");
            } else {
                wc.push_str(" AND");
            }
            wc.push_str(&format!(" collection_id = ?{}", params.len()));
        }
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "tags", &wc, &p);
    let offset = (page - 1) * size;
    let sql = format!(
        "SELECT * FROM tags {} ORDER BY id LIMIT {} OFFSET {}",
        wc, size, offset
    );
    let rows = conn
        .prepare(&sql)
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_tag)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    load_collection_cache(
        &state.db.conn(),
        &rows.iter().map(|t| t.collection_id).collect::<Vec<_>>(),
    );
    let list: Vec<Value> = rows.iter().map(tag_json).collect();
    page_ok(page, total, size, json!(list))
}

/// tag create body 版（body.user_id 已由调用方强制）
pub fn tag_create_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
) -> Json<Value> {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let color = b.get("color").and_then(|v| v.as_i64()).unwrap_or(0);
    let user_id = b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let collection_id = b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if name.is_empty() || user_id == 0 {
        return common::fail_h(101, "ParamsError", headers);
    }
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO tags (name, user_id, color, collection_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![name, user_id, color, collection_id, now_sql()],
    );
    drop(conn);
    if res.is_err() {
        return common::fail_msg(101, "OperationFailed".to_string());
    }
    common::success(Value::Null)
}

/// tag update body 版（force_user_id 时仅能改自己的）
pub fn tag_update_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
    force_user_id: Option<i64>,
) -> Json<Value> {
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id == 0 || name.is_empty() {
        return common::fail_h(101, "ParamsError", headers);
    }
    let conn = state.db.conn();
    if let Some(uid) = force_user_id {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tags WHERE id = ?1 AND user_id = ?2",
                [id, uid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            drop(conn);
            return common::fail_h(101, "ItemNotFound", headers);
        }
    }
    let _ = conn.execute(
        "UPDATE tags SET name=?1, user_id=?2, color=?3, collection_id=?4, updated_at=?5 WHERE id=?6",
        rusqlite::params![
            name,
            b.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("color").and_then(|v| v.as_i64()).unwrap_or(0),
            b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0),
            now_sql(),
            id
        ],
    );
    drop(conn);
    common::success(Value::Null)
}

/// address_book create body 版
pub fn address_book_create_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
) -> Json<Value> {
    let ab = match parse_address_book_body(b, true) {
        Ok(x) => x,
        Err((c, m)) => return common::fail_h(c, m, headers),
    };
    let conn = state.db.conn();
    if ab.collection_id > 0 && !check_collection_owner(&conn, ab.user_id, ab.collection_id) {
        drop(conn);
        return common::fail_h(101, "ParamsError", headers);
    }
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![ab.id, ab.user_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists > 0 {
        drop(conn);
        return common::fail_h(101, "ItemExists", headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
        rusqlite::params![
            ab.id, ab.username, ab.password, ab.hostname, ab.alias, ab.platform,
            ab.tags, ab.hash, ab.user_id, ab.force_always_relay as i64,
            ab.rdp_port, ab.rdp_username, ab.online as i64, ab.login_name,
            ab.same_server as i64, ab.collection_id, now,
        ],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// address_book update body 版（force_user_id 时仅能改自己的）
pub fn address_book_update_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
    force_user_id: Option<i64>,
) -> Json<Value> {
    let rid = b.get("row_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if rid == 0 {
        return common::fail_h(101, "ParamsError", headers);
    }
    let ab = match parse_address_book_body(b, true) {
        Ok(x) => x,
        Err((c, m)) => return common::fail_h(c, m, headers),
    };
    let conn = state.db.conn();
    if let Some(uid) = force_user_id {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM address_books WHERE row_id = ?1 AND user_id = ?2",
                [rid, uid],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists == 0 {
            drop(conn);
            return common::fail_h(101, "ItemNotFound", headers);
        }
    }
    if ab.collection_id > 0 && !check_collection_owner(&conn, ab.user_id, ab.collection_id) {
        drop(conn);
        return common::fail_h(101, "ParamsError", headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "UPDATE address_books SET id=?1, username=?2, password=?3, hostname=?4, alias=?5, platform=?6, tags=?7, hash=?8, user_id=?9, force_always_relay=?10, rdp_port=?11, rdp_username=?12, online=?13, login_name=?14, same_server=?15, collection_id=?16, updated_at=?17 WHERE row_id=?18",
        rusqlite::params![
            ab.id, ab.username, ab.password, ab.hostname, ab.alias, ab.platform,
            ab.tags, ab.hash, ab.user_id, ab.force_always_relay as i64,
            ab.rdp_port, ab.rdp_username, ab.online as i64, ab.login_name,
            ab.same_server as i64, ab.collection_id, now, rid,
        ],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// address_book batchCreateFromPeers body 版
pub fn address_book_batch_create_from_peers_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
) -> Json<Value> {
    let user_ids: Vec<i64> = b
        .get("user_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    let peer_ids: Vec<String> = b
        .get("peer_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if user_ids.is_empty() || peer_ids.is_empty() {
        return common::fail_h(101, "ParamsError", headers);
    }
    let conn = state.db.conn();
    let now = now_sql();
    for uid in &user_ids {
        for pid in &peer_ids {
            let peer = conn.query_row(
                &format!("SELECT {} FROM peers WHERE id = ?1", peer_cols()),
                [pid],
                row_to_peer_full,
            );
            let p = match peer {
                Ok(p) => p,
                Err(_) => continue,
            };
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM address_books WHERE id = ?1 AND user_id = ?2",
                    rusqlite::params![pid, uid],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if exists > 0 {
                continue;
            }
            let _ = conn.execute(
                "INSERT INTO address_books (id, username, password, hostname, alias, platform, tags, hash, user_id, force_always_relay, rdp_port, rdp_username, online, login_name, same_server, collection_id, created_at, updated_at) VALUES (?1,'','',?2,'',?3,'[]','',?4,0,'','',0,'',0,0,?5,?5)",
                rusqlite::params![p.id, p.hostname, platform_from_os(&p.os), uid, now],
            );
        }
    }
    drop(conn);
    common::success(Value::Null)
}

/// abcr create body 版（CheckForm 由 parse+abcr_check_form 完成）
pub fn abcr_create_body(
    state: &AdminState,
    headers: &axum::http::HeaderMap,
    b: &Value,
) -> Json<Value> {
    let t = match parse_abcr(b) {
        Some(t) => t,
        None => return common::fail_h(101, "ParamsError", headers),
    };
    let conn = state.db.conn();
    // owner 校验：collection 必须属于当前用户
    let owner: i64 = conn
        .query_row(
            "SELECT user_id FROM address_book_collections WHERE id = ?1",
            [t.collection_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if owner != t.user_id {
        drop(conn);
        return common::fail_h(101, "ParamsError", headers);
    }
    if let Err(m) = abcr_check_form(&conn, &t) {
        drop(conn);
        return common::fail_h(101, m, headers);
    }
    let now = now_sql();
    let res = conn.execute(
        "INSERT INTO address_book_collection_rules (user_id, collection_id, rule, type, to_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
        rusqlite::params![t.user_id, t.collection_id, t.rule, t.type_, t.to_id, now],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// abcr list（可强制 user_id）
pub fn abcr_list(state: &AdminState, q: &AbcrQuery, force_user_id: Option<i64>) -> Json<Value> {
    let (page, size) = page_args(&PageQuery {
        page: q.page,
        page_size: q.page_size,
    });
    let conn = state.db.conn();
    let uid = force_user_id.unwrap_or(q.user_id);
    let (mut wc, mut params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if uid > 0 {
        ("WHERE user_id = ?1".into(), vec![Box::new(uid)])
    } else {
        (String::new(), vec![])
    };
    if q.collection_id > 0 {
        params.push(Box::new(q.collection_id));
        if wc.is_empty() {
            wc.push_str(" WHERE");
        } else {
            wc.push_str(" AND");
        }
        wc.push_str(&format!(" collection_id = ?{}", params.len()));
    }
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total = count(&conn, "address_book_collection_rules", &wc, &p);
    let offset = (page - 1) * size;
    let rows = conn
        .prepare(&format!(
            "SELECT * FROM address_book_collection_rules {} ORDER BY id LIMIT {} OFFSET {}",
            wc, size, offset
        ))
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(p.as_slice(), row_to_abcr)
                .ok()
                .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(
        page,
        total,
        size,
        json!(rows.iter().map(abcr_json).collect::<Vec<_>>()),
    )
}

/// login_log 行 → LoginLog（供 my 复用）
pub fn login_log_from_row(row: &rusqlite::Row) -> rusqlite::Result<crate::models::LoginLog> {
    Ok(crate::models::LoginLog {
        id: row.get(0)?,
        user_id: row.get(1)?,
        client: row.get(2)?,
        device_id: row.get(3)?,
        uuid: row.get(4)?,
        ip: row.get(5)?,
        type_: row.get(6)?,
        platform: row.get(7)?,
        user_token_id: row.get(8)?,
        is_deleted: row.get(9)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(10)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
    })
}
