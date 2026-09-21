//! my.* 系列（对齐 Go http/controller/admin/my/*）——全部仅需登录，且强制 user_id = 当前用户

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::admin::AdminState;
use crate::api::common;
use crate::api::crud::{self, page_ok, AddressBookQuery};
use crate::auth;
use crate::models::User;

/// my 鉴权（仅登录）→ (user, token)
async fn auth_user(
    state: &AdminState,
    headers: &HeaderMap,
) -> Result<(User, String), (i64, &'static str)> {
    let config = state.config_manager.get().await;
    auth::backend_user_auth(&state.db, headers, config.app.token_expire_secs)
}

fn auth_err(e: (i64, &'static str)) -> Json<Value> {
    common::fail(e.0, e.1)
}

// ─────────────────────────── my/share_record ───────────────────────────

/// GET /api/admin/my/share_record/list
pub async fn handle_my_share_record_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<crud::ShareRecordQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::share_record_list(&state, &q, Some(user.id))
}

/// POST /api/admin/my/share_record/delete
pub async fn handle_my_share_record_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let res = conn.execute(
        "DELETE FROM share_records WHERE id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/my/share_record/batchDelete —— 先校验全部属于自己
pub async fn handle_my_share_record_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    // 校验：属于自己的记录数必须等于 ids 数
    let mut sql = format!(
        "SELECT COUNT(*) FROM share_records WHERE user_id = ?1 AND id IN ({})",
        placeholders
    );
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(user.id)];
    ids.iter().for_each(|i| params.push(Box::new(*i)));
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let total: i64 = conn
        .query_row(&sql, p.as_slice(), |r| r.get(0))
        .unwrap_or(0);
    if total != ids.len() as i64 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    sql = format!(
        "DELETE FROM share_records WHERE user_id = ?1 AND id IN ({})",
        placeholders
    );
    let res = conn.execute(&sql, p.as_slice());
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

// ─────────────────────────── my/address_book ───────────────────────────

/// GET /api/admin/my/address_book/list
pub async fn handle_my_address_book_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<AddressBookQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::ab_list(&state, &q, Some(user.id))
}

/// POST /api/admin/my/address_book/create
pub async fn handle_my_address_book_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_id"] = json!(user.id);
    crud::address_book_create_body(&state, &body)
}

/// POST /api/admin/my/address_book/update
pub async fn handle_my_address_book_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_id"] = json!(user.id);
    crud::address_book_update_body(&state, &body, Some(user.id))
}

/// POST /api/admin/my/address_book/delete
pub async fn handle_my_address_book_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let rid = b
        .get("row_id")
        .and_then(|v| v.as_i64())
        .or_else(|| b.get("id").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    if rid == 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let owner: Option<i64> = conn
        .query_row(
            "SELECT user_id FROM address_books WHERE row_id = ?1",
            [rid],
            |r| r.get(0),
        )
        .ok();
    match owner {
        Some(o) if o == user.id => {
            let res = conn.execute("DELETE FROM address_books WHERE row_id = ?1", [rid]);
            drop(conn);
            match res {
                Ok(_) => common::success(Value::Null),
                Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
            }
        }
        _ => {
            drop(conn);
            common::fail(101, "ItemNotFound")
        }
    }
}

/// POST /api/admin/my/address_book/batchCreateFromPeers
pub async fn handle_my_address_book_batch_create_from_peers(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_ids"] = json!([user.id]);
    crud::address_book_batch_create_from_peers_body(&state, &body)
}

/// POST /api/admin/my/address_book/batchUpdateTags —— 更新自己的多条 ab 的 tags
pub async fn handle_my_address_book_batch_update_tags(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    let tags = crud::tags_to_json(b.get("tags"));
    if ids.is_empty() {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let now = crud::now_sql();
    let mut n = 0;
    for rid in &ids {
        let res = conn.execute(
            "UPDATE address_books SET tags = ?1, updated_at = ?2 WHERE row_id = ?3 AND user_id = ?4",
            rusqlite::params![tags, now, rid, user.id],
        );
        if let Ok(c) = res {
            n += c;
        }
    }
    drop(conn);
    if n == 0 {
        return common::fail(101, "ItemNotFound");
    }
    common::success(Value::Null)
}

// ─────────────────────────── my/tag ───────────────────────────

/// GET /api/admin/my/tag/list
pub async fn handle_my_tag_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<crud::TagQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::tag_list(&state, &q, Some(user.id))
}

/// POST /api/admin/my/tag/create —— 强制 user_id = 当前用户
pub async fn handle_my_tag_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_id"] = json!(user.id);
    crud::tag_create_body(&state, &body)
}

/// POST /api/admin/my/tag/update —— 仅自己的
pub async fn handle_my_tag_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_id"] = json!(user.id);
    crud::tag_update_body(&state, &body, Some(user.id))
}

/// POST /api/admin/my/tag/delete
pub async fn handle_my_tag_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tags WHERE id = ?1 AND user_id = ?2",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    let res = conn.execute(
        "DELETE FROM tags WHERE id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

// ─────────────────────────── my/address_book_collection ───────────────────────────

/// GET /api/admin/my/address_book_collection/list
pub async fn handle_my_address_book_collection_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<crud::AbcQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::abc_list(&state, &q, Some(user.id))
}

/// POST /api/admin/my/address_book_collection/create
pub async fn handle_my_address_book_collection_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let now = crud::now_sql();
    let res = conn.execute(
        "INSERT INTO address_book_collections (user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
        rusqlite::params![user.id, name, now],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/my/address_book_collection/update
pub async fn handle_my_address_book_collection_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if id <= 0 || name.is_empty() {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collections WHERE id = ?1 AND user_id = ?2",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    let res = conn.execute(
        "UPDATE address_book_collections SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        rusqlite::params![name, crud::now_sql(), id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/my/address_book_collection/delete
pub async fn handle_my_address_book_collection_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collections WHERE id = ?1 AND user_id = ?2",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    // 级联：rules + address_books + collection（对齐 Go service.AddressBookCollection.Delete）
    let _ = conn.execute_batch("BEGIN");
    let _ = conn.execute(
        "DELETE FROM address_book_collection_rules WHERE collection_id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    let _ = conn.execute(
        "DELETE FROM address_books WHERE collection_id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    let res = conn.execute(
        "DELETE FROM address_book_collections WHERE id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    let _ = conn.execute_batch("COMMIT");
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

// ─────────────────────────── my/address_book_collection_rule ───────────────────────────

/// GET /api/admin/my/address_book_collection_rule/list
pub async fn handle_my_address_book_collection_rule_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<crud::AbcrQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::abcr_list(&state, &q, Some(user.id))
}

/// POST /api/admin/my/address_book_collection_rule/create —— CheckForm（owner 版）
pub async fn handle_my_address_book_collection_rule_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let mut body = b.clone();
    body["user_id"] = json!(user.id);
    crud::abcr_create_body(&state, &body)
}

/// POST /api/admin/my/address_book_collection_rule/update
pub async fn handle_my_address_book_collection_rule_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let rule = b.get("rule").and_then(|v| v.as_i64()).unwrap_or(0);
    let type_ = b.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
    let to_id = b.get("to_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let collection_id = b.get("collection_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 || collection_id <= 0 || to_id <= 0 {
        return common::fail(101, "ParamsError");
    }
    if !(1..=3).contains(&rule) || (type_ != 1 && type_ != 2) {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    // 只能改自己的 rule
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collection_rules WHERE id = ?1 AND user_id = ?2",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    // collection owner 校验
    let owner: i64 = conn
        .query_row(
            "SELECT user_id FROM address_book_collections WHERE id = ?1",
            [collection_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if owner != user.id {
        drop(conn);
        return common::fail(101, "CollectionNotFound");
    }
    let res = conn.execute(
        "UPDATE address_book_collection_rules SET rule = ?1, type = ?2, to_id = ?3, collection_id = ?4, updated_at = ?5 WHERE id = ?6 AND user_id = ?7",
        rusqlite::params![rule, type_, to_id, collection_id, crud::now_sql(), id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/my/address_book_collection_rule/delete
pub async fn handle_my_address_book_collection_rule_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM address_book_collection_rules WHERE id = ?1 AND user_id = ?2",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    let res = conn.execute(
        "DELETE FROM address_book_collection_rules WHERE id = ?1 AND user_id = ?2",
        [id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

// ─────────────────────────── my/peer ───────────────────────────

/// GET /api/admin/my/peer/list
pub async fn handle_my_peer_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<crud::PeerQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    crud::peer_list(&state, &q, Some(user.id))
}

// ─────────────────────────── my/login_log ───────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct MyLoginLogQuery {
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: i64,
    #[serde(default)]
    pub type_: Option<String>,
}

/// GET /api/admin/my/login_log/list —— 仅自己的 + is_deleted = 0
pub async fn handle_my_login_log_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<MyLoginLogQuery>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let (page, size) = (
        if q.page <= 0 { 1 } else { q.page },
        if q.page_size <= 0 { 10 } else { q.page_size },
    );
    let conn = state.db.conn();
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM login_logs WHERE user_id = ?1 AND is_deleted = 0",
            [user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let offset = (page - 1) * size;
    let rows: Vec<Value> = conn
        .prepare(
            "SELECT id, user_id, client, device_id, uuid, ip, type, platform, user_token_id, is_deleted, created_at, updated_at FROM login_logs WHERE user_id = ?1 AND is_deleted = 0 ORDER BY id DESC LIMIT ?2 OFFSET ?3",
        )
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map([user.id, size, offset], |row| {
                let ll = crate::api::crud::login_log_from_row(row)?;
                Ok(json!({
                    "id": ll.id, "user_id": ll.user_id, "client": ll.client,
                    "device_id": ll.device_id, "uuid": ll.uuid, "ip": ll.ip,
                    "type": ll.type_, "platform": ll.platform,
                    "user_token_id": ll.user_token_id, "is_deleted": ll.is_deleted,
                    "created_at": ll.created_at, "updated_at": ll.updated_at,
                }))
            })
            .ok().map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    drop(conn);
    page_ok(page, total, size, json!(rows))
}

/// POST /api/admin/my/login_log/delete —— 软删
pub async fn handle_my_login_log_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let id = b.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    if id <= 0 {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM login_logs WHERE id = ?1 AND user_id = ?2 AND is_deleted = 0",
            [id, user.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        drop(conn);
        return common::fail(101, "ItemNotFound");
    }
    let res = conn.execute(
        "UPDATE login_logs SET is_deleted = 1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        rusqlite::params![crud::now_sql(), id, user.id],
    );
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}

/// POST /api/admin/my/login_log/batchDelete —— 软删（BatchSoftDelete）
pub async fn handle_my_login_log_batch_delete(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(b): Json<Value>,
) -> Json<Value> {
    let (user, _) = match auth_user(&state, &headers).await {
        Ok(x) => x,
        Err(e) => return auth_err(e),
    };
    let ids: Vec<i64> = b
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return common::fail(101, "ParamsError");
    }
    let conn = state.db.conn();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "UPDATE login_logs SET is_deleted = 1, updated_at = ?1 WHERE user_id = ?2 AND id IN ({})",
        placeholders
    );
    let mut params: Vec<Box<dyn rusqlite::ToSql>> =
        vec![Box::new(crud::now_sql()), Box::new(user.id)];
    ids.iter().for_each(|i| params.push(Box::new(*i)));
    let p: Vec<&dyn rusqlite::ToSql> = params.iter().map(|x| x.as_ref()).collect();
    let res = conn.execute(&sql, p.as_slice());
    drop(conn);
    match res {
        Ok(_) => common::success(Value::Null),
        Err(_) => common::fail_msg(101, "OperationFailed".to_string()),
    }
}
