//! 认证：BackendUserAuth / RustAuth / AdminPrivilege
//!
//! 对齐 Go middleware/。管理面用 api-token 头，客户端用 Authorization: Bearer {token}。

use axum::http::HeaderMap;

use crate::db::Db;
use crate::models::{User, UserToken};

/// 通过 token 查用户（对齐 Go service.UserService.InfoByAccessToken）
pub fn user_by_token(db: &Db, token: &str) -> (Option<User>, Option<UserToken>) {
    let conn = db.conn();
    let ut = conn
        .query_row(
            "SELECT * FROM user_tokens WHERE token = ?1 LIMIT 1",
            [token],
            row_to_user_token,
        )
        .ok();
    match ut {
        Some(ut) => {
            // 过期校验
            if ut.expired_at < crate::db::now_unix() {
                return (None, Some(ut));
            }
            let u = conn
                .query_row(
                    "SELECT * FROM users WHERE id = ?1",
                    [ut.user_id],
                    row_to_user,
                )
                .ok();
            (u, Some(ut))
        }
        None => (None, None),
    }
}

/// 校验并自动续期（剩余时间 < expire/3000 时刷新过期时间）
pub fn auto_refresh_token(db: &Db, ut: &UserToken, token_expire_secs: i64) {
    let remaining = ut.expired_at - crate::db::now_unix();
    if remaining < token_expire_secs / 3000 {
        let new_expired = crate::db::now_unix() + token_expire_secs;
        let conn = db.conn();
        let _ = conn.execute(
            "UPDATE user_tokens SET expired_at = ?1 WHERE id = ?2",
            rusqlite::params![new_expired, ut.id],
        );
    }
}

/// 管理面鉴权：api-token 头 → 用户。失败返回错误信息。
/// 返回 (Result<user, (code, msg)>, token)。
pub fn backend_user_auth(
    db: &Db,
    headers: &HeaderMap,
    token_expire_secs: i64,
) -> Result<(User, String), (i64, &'static str)> {
    let token = match headers.get("api-token") {
        Some(v) => match v.to_str() {
            Ok(s) => s.trim().to_string(),
            Err(_) => return Err((403, "NeedLogin")),
        },
        None => return Err((403, "NeedLogin")),
    };
    let (user, ut) = user_by_token(db, &token);
    let user = match user {
        Some(u) => u,
        None => return Err((403, "NeedLogin")),
    };
    if !user.is_enabled() {
        return Err((403, "NeedLogin"));
    }
    if let Some(ut) = ut {
        auto_refresh_token(db, &ut, token_expire_secs);
    }
    Ok((user, token))
}

/// 客户端鉴权：Authorization: Bearer {token}。失败返回 401 Unauthorized。
#[allow(clippy::result_unit_err)]
pub fn rust_auth(db: &Db, headers: &HeaderMap, token_expire_secs: i64) -> Result<User, ()> {
    let auth = match headers.get("authorization") {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return Err(()),
        },
        None => return Err(()),
    };
    if auth.len() <= 7 || !auth.starts_with("Bearer ") {
        return Err(());
    }
    let token = auth[7..].to_string();
    let (user, ut) = user_by_token(db, &token);
    let user = match user {
        Some(u) if u.is_enabled() => u,
        _ => return Err(()),
    };
    if let Some(ut) = ut {
        auto_refresh_token(db, &ut, token_expire_secs);
    }
    Ok(user)
}

/// 管理员权限校验
pub fn is_admin(user: &User) -> bool {
    user.is_admin()
}

/// 从 HeaderMap 取 api-token（OIDC auth-query 前预处理用）
pub fn extract_api_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("api-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        email: row.get("email")?,
        password: row.get("password")?,
        nickname: row.get("nickname")?,
        avatar: row.get("avatar")?,
        group_id: row.get("group_id")?,
        is_admin: row.get::<_, i64>("is_admin")? != 0,
        status: row.get("status")?,
        remark: row.get("remark")?,
        tfa_secret: row.get("tfa_secret")?,
        created_at: crate::db::format_autotime(&row.get::<_, String>("created_at")?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>("updated_at")?),
    })
}

fn row_to_user_token(row: &rusqlite::Row) -> rusqlite::Result<UserToken> {
    Ok(UserToken {
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
