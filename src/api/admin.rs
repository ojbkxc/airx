//! 管理面 API：登录 / 认证 / 配置 / 当前用户 / 登出

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::common;
use crate::auth;
use crate::config::ConfigManager;
use crate::db::Db;
use crate::models::{LoginLog, User};

/// 管理面共享状态
#[derive(Clone)]
pub struct AdminState {
    pub config_manager: Arc<ConfigManager>,
    pub db: Arc<Db>,
    /// 登录限流器（进程内存态，对齐 Go global.LoginLimiter）
    pub login_limiter: Arc<crate::login_limiter::LoginLimiter>,
}

/// 路由注册（对齐 Go http/router/admin.go）
pub fn routes(state: AdminState) -> Router<AdminState> {
    // 免认证组
    let login_routes = Router::new()
        .route("/api/admin/login", post(handle_login))
        .route("/api/admin/captcha", get(handle_captcha))
        .route("/api/admin/logout", post(handle_logout))
        .route("/api/admin/login-options", get(handle_login_options))
        .route(
            "/api/admin/oidc/auth",
            post(crate::api::oauth::handle_admin_oidc_auth),
        )
        .route(
            "/api/admin/oidc/auth-query",
            get(crate::api::oauth::handle_admin_oidc_auth_query),
        )
        .route("/api/admin/user/register", post(handle_register))
        .route("/api/admin/config/admin", get(handle_config_admin));

    // 需登录组
    let authed_routes = Router::new()
        .route("/api/admin/config/server", get(handle_config_server))
        .route("/api/admin/config/app", get(handle_config_app))
        .route("/api/admin/user/current", get(handle_user_current))
        .route("/api/admin/user/changeCurPwd", post(handle_change_cur_pwd))
        .route("/api/admin/user/myOauth", post(handle_my_oauth))
        .route("/api/admin/user/groupUsers", post(handle_group_users))
        .route(
            "/api/admin/peer/simpleData",
            post(crate::api::crud::handle_peer_simple_data),
        )
        .route(
            "/api/admin/address_book/shareByWebClient",
            post(crate::api::crud::handle_address_book_share_by_webclient),
        )
        .route(
            "/api/admin/rustdesk/sendCmd",
            post(crate::api::crud::handle_rustdesk_send_cmd),
        )
        .route(
            "/api/admin/rustdesk/cmdList",
            get(crate::api::crud::handle_rustdesk_cmd_list),
        )
        .route(
            "/api/admin/rustdesk/cmdDelete",
            post(crate::api::crud::handle_rustdesk_cmd_delete),
        )
        .route(
            "/api/admin/rustdesk/cmdCreate",
            post(crate::api::crud::handle_rustdesk_cmd_create),
        )
        .route(
            "/api/admin/dashboard/stats",
            get(crate::api::crud::handle_dashboard_stats),
        )
        .route(
            "/api/admin/oauth/confirm",
            post(crate::api::oauth::handle_oauth_confirm),
        )
        .route(
            "/api/admin/oauth/bind",
            post(crate::api::oauth::handle_oauth_bind),
        )
        .route(
            "/api/admin/oauth/bindConfirm",
            post(crate::api::oauth::handle_oauth_bind_confirm),
        )
        .route(
            "/api/admin/oauth/unbind",
            post(crate::api::oauth::handle_oauth_unbind),
        )
        .route(
            "/api/admin/oauth/info",
            get(crate::api::oauth::handle_oauth_info),
        )
        .route(
            "/api/admin/oauth/list",
            get(crate::api::crud::handle_oauth_list),
        )
        .route(
            "/api/admin/oauth/detail/:id",
            get(crate::api::crud::handle_oauth_detail),
        )
        .route(
            "/api/admin/oauth/create",
            post(crate::api::crud::handle_oauth_create),
        )
        .route(
            "/api/admin/oauth/update",
            post(crate::api::crud::handle_oauth_update),
        )
        .route(
            "/api/admin/oauth/delete",
            post(crate::api::crud::handle_oauth_delete),
        )
        // my.* 系列
        .route(
            "/api/admin/my/share_record/list",
            get(crate::api::my::handle_my_share_record_list),
        )
        .route(
            "/api/admin/my/share_record/delete",
            post(crate::api::my::handle_my_share_record_delete),
        )
        .route(
            "/api/admin/my/share_record/batchDelete",
            post(crate::api::my::handle_my_share_record_batch_delete),
        )
        .route(
            "/api/admin/my/address_book/list",
            get(crate::api::my::handle_my_address_book_list),
        )
        .route(
            "/api/admin/my/address_book/create",
            post(crate::api::my::handle_my_address_book_create),
        )
        .route(
            "/api/admin/my/address_book/update",
            post(crate::api::my::handle_my_address_book_update),
        )
        .route(
            "/api/admin/my/address_book/delete",
            post(crate::api::my::handle_my_address_book_delete),
        )
        .route(
            "/api/admin/my/address_book/batchCreateFromPeers",
            post(crate::api::my::handle_my_address_book_batch_create_from_peers),
        )
        .route(
            "/api/admin/my/address_book/batchUpdateTags",
            post(crate::api::my::handle_my_address_book_batch_update_tags),
        )
        .route(
            "/api/admin/my/tag/list",
            get(crate::api::my::handle_my_tag_list),
        )
        .route(
            "/api/admin/my/tag/create",
            post(crate::api::my::handle_my_tag_create),
        )
        .route(
            "/api/admin/my/tag/update",
            post(crate::api::my::handle_my_tag_update),
        )
        .route(
            "/api/admin/my/tag/delete",
            post(crate::api::my::handle_my_tag_delete),
        )
        .route(
            "/api/admin/my/address_book_collection/list",
            get(crate::api::my::handle_my_address_book_collection_list),
        )
        .route(
            "/api/admin/my/address_book_collection/create",
            post(crate::api::my::handle_my_address_book_collection_create),
        )
        .route(
            "/api/admin/my/address_book_collection/update",
            post(crate::api::my::handle_my_address_book_collection_update),
        )
        .route(
            "/api/admin/my/address_book_collection/delete",
            post(crate::api::my::handle_my_address_book_collection_delete),
        )
        .route(
            "/api/admin/my/address_book_collection_rule/list",
            get(crate::api::my::handle_my_address_book_collection_rule_list),
        )
        .route(
            "/api/admin/my/address_book_collection_rule/create",
            post(crate::api::my::handle_my_address_book_collection_rule_create),
        )
        .route(
            "/api/admin/my/address_book_collection_rule/update",
            post(crate::api::my::handle_my_address_book_collection_rule_update),
        )
        .route(
            "/api/admin/my/address_book_collection_rule/delete",
            post(crate::api::my::handle_my_address_book_collection_rule_delete),
        )
        .route(
            "/api/admin/my/peer/list",
            get(crate::api::my::handle_my_peer_list),
        )
        .route(
            "/api/admin/my/login_log/list",
            get(crate::api::my::handle_my_login_log_list),
        )
        .route(
            "/api/admin/my/login_log/delete",
            post(crate::api::my::handle_my_login_log_delete),
        )
        .route(
            "/api/admin/my/login_log/batchDelete",
            post(crate::api::my::handle_my_login_log_batch_delete),
        );

    // 需管理员组
    let admin_routes = Router::new()
        // user
        .route(
            "/api/admin/user/list",
            get(crate::api::crud::handle_user_list),
        )
        .route(
            "/api/admin/user/detail/:id",
            get(crate::api::crud::handle_user_detail),
        )
        .route(
            "/api/admin/user/create",
            post(crate::api::crud::handle_user_create),
        )
        .route(
            "/api/admin/user/update",
            post(crate::api::crud::handle_user_update),
        )
        .route(
            "/api/admin/user/delete",
            post(crate::api::crud::handle_user_delete),
        )
        .route(
            "/api/admin/user/changePwd",
            post(crate::api::crud::handle_user_change_pwd),
        )
        // group
        .route(
            "/api/admin/group/list",
            get(crate::api::crud::handle_group_list),
        )
        .route(
            "/api/admin/group/detail/:id",
            get(crate::api::crud::handle_group_detail),
        )
        .route(
            "/api/admin/group/create",
            post(crate::api::crud::handle_group_create),
        )
        .route(
            "/api/admin/group/update",
            post(crate::api::crud::handle_group_update),
        )
        .route(
            "/api/admin/group/delete",
            post(crate::api::crud::handle_group_delete),
        )
        // device_group
        .route(
            "/api/admin/device_group/list",
            get(crate::api::crud::handle_device_group_list),
        )
        .route(
            "/api/admin/device_group/detail/:id",
            get(crate::api::crud::handle_device_group_detail),
        )
        .route(
            "/api/admin/device_group/create",
            post(crate::api::crud::handle_device_group_create),
        )
        .route(
            "/api/admin/device_group/update",
            post(crate::api::crud::handle_device_group_update),
        )
        .route(
            "/api/admin/device_group/delete",
            post(crate::api::crud::handle_device_group_delete),
        )
        // tag
        .route(
            "/api/admin/tag/list",
            get(crate::api::crud::handle_tag_list),
        )
        .route(
            "/api/admin/tag/detail/:id",
            get(crate::api::crud::handle_tag_detail),
        )
        .route(
            "/api/admin/tag/create",
            post(crate::api::crud::handle_tag_create),
        )
        .route(
            "/api/admin/tag/update",
            post(crate::api::crud::handle_tag_update),
        )
        .route(
            "/api/admin/tag/delete",
            post(crate::api::crud::handle_tag_delete),
        )
        // address_book
        .route(
            "/api/admin/address_book/list",
            get(crate::api::crud::handle_address_book_list),
        )
        .route(
            "/api/admin/address_book/create",
            post(crate::api::crud::handle_address_book_create),
        )
        .route(
            "/api/admin/address_book/update",
            post(crate::api::crud::handle_address_book_update),
        )
        .route(
            "/api/admin/address_book/delete",
            post(crate::api::crud::handle_address_book_delete),
        )
        .route(
            "/api/admin/address_book/batchCreate",
            post(crate::api::crud::handle_address_book_batch_create),
        )
        .route(
            "/api/admin/address_book/batchCreateFromPeers",
            post(crate::api::crud::handle_address_book_batch_create_from_peers),
        )
        // peer
        .route(
            "/api/admin/peer/list",
            get(crate::api::crud::handle_peer_list),
        )
        .route(
            "/api/admin/peer/detail/:id",
            get(crate::api::crud::handle_peer_detail),
        )
        .route(
            "/api/admin/peer/create",
            post(crate::api::crud::handle_peer_create),
        )
        .route(
            "/api/admin/peer/update",
            post(crate::api::crud::handle_peer_update),
        )
        .route(
            "/api/admin/peer/delete",
            post(crate::api::crud::handle_peer_delete),
        )
        .route(
            "/api/admin/peer/batchDelete",
            post(crate::api::crud::handle_peer_batch_delete),
        )
        // login_log
        .route(
            "/api/admin/login_log/list",
            get(crate::api::crud::handle_login_log_list),
        )
        .route(
            "/api/admin/login_log/delete",
            post(crate::api::crud::handle_login_log_delete),
        )
        .route(
            "/api/admin/login_log/batchDelete",
            post(crate::api::crud::handle_login_log_batch_delete),
        )
        // audit_conn
        .route(
            "/api/admin/audit_conn/list",
            get(crate::api::crud::handle_audit_conn_list),
        )
        .route(
            "/api/admin/audit_conn/delete",
            post(crate::api::crud::handle_audit_conn_delete),
        )
        .route(
            "/api/admin/audit_conn/batchDelete",
            post(crate::api::crud::handle_audit_conn_batch_delete),
        )
        // audit_file
        .route(
            "/api/admin/audit_file/list",
            get(crate::api::crud::handle_audit_file_list),
        )
        .route(
            "/api/admin/audit_file/delete",
            post(crate::api::crud::handle_audit_file_delete),
        )
        .route(
            "/api/admin/audit_file/batchDelete",
            post(crate::api::crud::handle_audit_file_batch_delete),
        )
        // address_book_collection
        .route(
            "/api/admin/address_book_collection/list",
            get(crate::api::crud::handle_abc_list),
        )
        .route(
            "/api/admin/address_book_collection/detail/:id",
            get(crate::api::crud::handle_abc_detail),
        )
        .route(
            "/api/admin/address_book_collection/create",
            post(crate::api::crud::handle_abc_create),
        )
        .route(
            "/api/admin/address_book_collection/update",
            post(crate::api::crud::handle_abc_update),
        )
        .route(
            "/api/admin/address_book_collection/delete",
            post(crate::api::crud::handle_abc_delete),
        )
        // address_book_collection_rule
        .route(
            "/api/admin/address_book_collection_rule/list",
            get(crate::api::crud::handle_abcr_list),
        )
        .route(
            "/api/admin/address_book_collection_rule/detail/:id",
            get(crate::api::crud::handle_abcr_detail),
        )
        .route(
            "/api/admin/address_book_collection_rule/create",
            post(crate::api::crud::handle_abcr_create),
        )
        .route(
            "/api/admin/address_book_collection_rule/update",
            post(crate::api::crud::handle_abcr_update),
        )
        .route(
            "/api/admin/address_book_collection_rule/delete",
            post(crate::api::crud::handle_abcr_delete),
        )
        // user_token
        .route(
            "/api/admin/user_token/list",
            get(crate::api::crud::handle_user_token_list),
        )
        .route(
            "/api/admin/user_token/delete",
            post(crate::api::crud::handle_user_token_delete),
        )
        .route(
            "/api/admin/user_token/batchDelete",
            post(crate::api::crud::handle_user_token_batch_delete),
        )
        // share_record
        .route(
            "/api/admin/share_record/list",
            get(crate::api::crud::handle_share_record_list),
        )
        .route(
            "/api/admin/share_record/delete",
            post(crate::api::crud::handle_share_record_delete),
        )
        .route(
            "/api/admin/share_record/batchDelete",
            post(crate::api::crud::handle_share_record_batch_delete),
        );

    Router::new()
        .merge(login_routes)
        .merge(authed_routes)
        .merge(admin_routes)
        .with_state(state)
}

// ─────────────────────────── 登录 ───────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub captcha: String,
    #[serde(default)]
    pub captcha_id: String,
}

#[derive(Debug, Serialize)]
struct LoginPayload {
    username: String,
    email: String,
    avatar: String,
    token: String,
    route_names: Vec<String>,
    nickname: String,
}

/// POST /api/admin/login
pub async fn handle_login(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<LoginForm>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    if config.app.disable_pwd_login {
        return common::fail_h(101, "PwdLoginDisabled", &headers);
    }

    // 登录限流（对齐 Go LoginLimiter）：封禁 → 423；达到阈值 → 要求验证码
    let ip = crate::utils::client_ip(&headers, "127.0.0.1");
    let (banned, need_captcha) = state.login_limiter.check_security_status(&ip);
    if banned {
        return common::fail_h(423, "Banned", &headers);
    }
    if need_captcha
        && (body.captcha_id.is_empty()
            || body.captcha.is_empty()
            || !state
                .login_limiter
                .verify_captcha(&body.captcha_id, &body.captcha))
    {
        return common::fail_h(101, "CaptchaError", &headers);
    }

    // 查用户
    let user = user_by_username(&state.db, &body.username);
    let user = match user {
        Some(u) => u,
        None => {
            state.login_limiter.record_failed_attempt(&ip);
            let (_, need) = state.login_limiter.check_security_status(&ip);
            let code = if need { 110 } else { 101 };
            return common::fail_h(code, "UsernameOrPasswordError", &headers);
        }
    };
    // 校验密码
    let (ok, new_hash) = crate::utils::verify_password(&user.password, &body.password);
    if !ok {
        state.login_limiter.record_failed_attempt(&ip);
        let (_, need) = state.login_limiter.check_security_status(&ip);
        let code = if need { 110 } else { 101 };
        return common::fail_h(code, "UsernameOrPasswordError", &headers);
    }
    if let Some(new_hash) = new_hash {
        let conn = state.db.conn();
        let _ = conn.execute(
            "UPDATE users SET password = ?1 WHERE id = ?2",
            rusqlite::params![new_hash, user.id],
        );
    }
    // 用户是否启用
    if !user.is_enabled() {
        return common::fail_h(101, "UserDisabled", &headers);
    }

    state.login_limiter.remove_attempts(&ip);
    let token = do_login(
        &state,
        &user,
        &LoginLog {
            client: "webadmin".to_string(),
            uuid: String::new(),
            ip,
            type_: "account".to_string(),
            platform: body.platform.clone(),
            ..Default::default()
        },
    );
    login_success_payload(&state, &user, &token)
}

/// 执行登录：生成 token、写 user_tokens + login_logs、绑定 uuid
pub fn do_login(state: &AdminState, user: &User, llog: &LoginLog) -> String {
    // do_login 是同步函数，不能 await config_manager.get()；用全局快照
    let token_expire_secs = crate::config::snapshot().app.token_expire_secs;
    let token = crate::utils::generate_token(&user.username);
    let now = crate::db::now_unix();
    let expired = now + token_expire_secs;
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO user_tokens (user_id, device_uuid, device_id, token, expired_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), datetime('now'))",
        rusqlite::params![user.id, llog.uuid, llog.device_id, token, expired],
    );
    let _ = res;
    // 写登录日志
    let _ = conn.execute(
        "INSERT INTO login_logs (user_id, client, device_id, uuid, ip, type, platform, user_token_id, is_deleted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, datetime('now'), datetime('now'))",
        rusqlite::params![
            user.id,
            llog.client,
            llog.device_id,
            llog.uuid,
            llog.ip,
            llog.type_,
            llog.platform
        ],
    );
    // 绑定 uuid→userId（对齐 Go Login 里 UuidBindUserId）
    if !llog.uuid.is_empty() {
        let _ = conn.execute(
            "UPDATE peers SET user_id = ?1 WHERE uuid = ?2",
            rusqlite::params![user.id, llog.uuid],
        );
    }
    token
}

/// 组装登录成功 payload
pub fn login_success_payload(_state: &AdminState, user: &User, token: &str) -> Json<Value> {
    let route_names = if user.is_admin() {
        vec!["*".to_string()]
    } else {
        crate::models::user_route_names()
    };
    common::success(json!(LoginPayload {
        username: user.username.clone(),
        email: user.email.clone(),
        avatar: user.avatar.clone(),
        token: token.to_string(),
        route_names,
        nickname: user.nickname.clone(),
    }))
}

/// GET /api/admin/user/current
pub async fn handle_user_current(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    match auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
        Ok((user, token)) => login_success_payload(&state, &user, &token),
        Err((code, msg)) => common::fail_h(code, msg, &headers),
    }
}

/// POST /api/admin/logout
pub async fn handle_logout(State(state): State<AdminState>, headers: HeaderMap) -> Json<Value> {
    let config = state.config_manager.get().await;
    let token = headers
        .get("api-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    if !token.is_empty() {
        let conn = state.db.conn();
        let _ = conn.execute("DELETE FROM user_tokens WHERE token = ?1", [&token]);
    }
    let _ = config;
    common::success(Value::Null)
}

/// GET /api/admin/login-options
pub async fn handle_login_options(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let ops = crate::api::oauth::oauth_provider_ops(&state);
    let ip = crate::utils::client_ip(&headers, "127.0.0.1");
    let (banned, need_captcha) = state.login_limiter.check_security_status(&ip);
    if banned {
        return common::fail_h(101, "LoginBanned", &headers);
    }
    common::success(json!({
        "ops": ops,
        "register": config.app.register,
        "need_captcha": need_captcha,
        "disable_pwd": config.app.disable_pwd_login,
        "auto_oidc": config.app.disable_pwd_login && ops.len() == 1,
    }))
}

/// GET /api/admin/captcha（对齐 Go Login.Captcha）
pub async fn handle_captcha(State(state): State<AdminState>, headers: HeaderMap) -> Json<Value> {
    let ip = crate::utils::client_ip(&headers, "127.0.0.1");
    let (banned, need_captcha) = state.login_limiter.check_security_status(&ip);
    if banned {
        return common::fail_h(101, "LoginBanned", &headers);
    }
    if !need_captcha {
        return common::fail_h(101, "NoCaptchaRequired", &headers);
    }
    match state.login_limiter.require_captcha() {
        Some((id, _answer, b64)) => common::success(json!({
            "captcha": { "id": id, "b64": b64 },
        })),
        None => common::fail_h(101, "CaptchaError", &headers),
    }
}

/// POST /api/admin/user/register
pub async fn handle_register(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    if !config.app.register {
        return common::fail_h(101, "RegisterClosed", &headers);
    }
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let email = body.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if username.is_empty() || password.len() < 4 {
        return common::fail_h(101, "ParamsError", &headers);
    }
    // 用户名已存在
    if user_by_username(&state.db, username).is_some() {
        return common::fail_h(101, "OperationFailed", &headers);
    }
    let hash = crate::utils::hash_password(password);
    let status = if config.app.register_status == 2 {
        2
    } else {
        1
    };
    let conn = state.db.conn();
    let res = conn.execute(
        "INSERT INTO users (username, email, password, nickname, avatar, group_id, is_admin, status, remark, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, '', 1, 0, ?5, '', datetime('now'), datetime('now'))",
        rusqlite::params![username, email, hash, username, status],
    );
    if res.is_err() {
        return common::fail_h(101, "OperationFailed", &headers);
    }
    let uid = conn.last_insert_rowid();
    let user = user_by_id(&state.db, uid).unwrap_or_default();
    if status == 2 {
        return common::fail_h(101, "RegisterSuccessWaitAdminConfirm", &headers);
    }
    let reg_ip = crate::utils::client_ip(&headers, "127.0.0.1");
    let token = do_login(
        &state,
        &user,
        &LoginLog {
            client: "webadmin".to_string(),
            ip: reg_ip,
            type_: "account".to_string(),
            ..Default::default()
        },
    );
    login_success_payload(&state, &user, &token)
}

// ─────────────────────────── 配置 ───────────────────────────

/// GET /api/admin/config/server
pub async fn handle_config_server(State(state): State<AdminState>) -> Json<Value> {
    let config = state.config_manager.get().await;
    common::success(json!({
        "id_server": config.rustdesk.id_server,
        "key": config.rustdesk.key,
        "relay_server": config.rustdesk.relay_server,
        "api_server": config.rustdesk.api_server,
    }))
}

/// GET /api/admin/config/app
pub async fn handle_config_app(State(state): State<AdminState>) -> Json<Value> {
    let config = state.config_manager.get().await;
    common::success(json!({ "web_client": config.app.web_client }))
}

/// GET /api/admin/config/admin
pub async fn handle_config_admin(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let token = headers
        .get("api-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let mut title = config.admin.title.clone();
    if title.is_empty() {
        title = "AIRX Admin".to_string();
    }
    if token.is_empty() {
        return common::success(json!({ "title": title }));
    }
    let (user, _) = auth::user_by_token(&state.db, &token);
    if let Some(u) = user {
        if u.is_enabled() {
            let mut hello = config.admin.hello.clone();
            if hello.is_empty() && !config.admin.hello_file.is_empty() {
                if let Ok(b) = std::fs::read(crate::config::expand_path(&config.admin.hello_file)) {
                    if let Ok(s) = String::from_utf8(b) {
                        hello = s;
                    }
                }
            }
            hello = hello.replace("{{username}}", &u.username);
            return common::success(json!({ "title": title, "hello": hello }));
        }
    }
    common::success(json!({ "title": title }))
}

/// POST /api/admin/user/changeCurPwd
pub async fn handle_change_cur_pwd(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) = match auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs)
    {
        Ok(v) => v,
        Err((code, msg)) => return common::fail_h(code, msg, &headers),
    };
    let old = body
        .get("old_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new = body
        .get("new_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // 旧密码校验（账号已有密码时）
    if !user.password.is_empty() {
        let (ok, _) = crate::utils::verify_password(&user.password, old);
        if !ok {
            return common::fail_h(101, "OldPasswordError", &headers);
        }
    }
    let hash = crate::utils::hash_password(new);
    let conn = state.db.conn();
    let _ = conn.execute(
        "UPDATE users SET password = ?1 WHERE id = ?2",
        rusqlite::params![hash, user.id],
    );
    // 清空该用户 token
    let _ = conn.execute("DELETE FROM user_tokens WHERE user_id = ?1", [user.id]);
    common::success(Value::Null)
}

/// POST /api/admin/user/myOauth
pub async fn handle_my_oauth(State(state): State<AdminState>, headers: HeaderMap) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) = match auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs)
    {
        Ok(v) => v,
        Err((code, msg)) => return common::fail_h(code, msg, &headers),
    };
    let ops = crate::api::oauth::oauth_provider_ops(&state);
    let conn = state.db.conn();
    let mut stmt = match conn.prepare("SELECT op FROM user_thirds WHERE user_id = ?1") {
        Ok(s) => s,
        Err(_) => return common::fail_h(101, "OperationFailed", &headers),
    };
    let bound: Vec<String> = stmt
        .query_map([user.id], |r| r.get(0))
        .ok()
        .and_then(|it| it.collect::<Result<Vec<_>, _>>().ok())
        .unwrap_or_default();
    drop(stmt);
    let items: Vec<Value> = ops
        .iter()
        .map(|op| {
            let status = if bound.contains(op) { 1 } else { 0 };
            json!({ "op": op, "status": status })
        })
        .collect();
    common::success(json!(items))
}

/// POST /api/admin/user/groupUsers
pub async fn handle_group_users(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (_, _) = match auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
        Ok(v) => v,
        Err((code, msg)) => return common::fail_h(code, msg, &headers),
    };
    let groups = crate::api::crud::list_groups_json(&state);
    let users = crate::api::crud::list_all_users_json(&state);
    common::success(json!({ "groups": groups, "users": users }))
}

// ─────────────────────────── 辅助 ───────────────────────────

/// 按用户名查用户
pub fn user_by_username(db: &Db, username: &str) -> Option<User> {
    let conn = db.conn();
    conn.query_row(
        "SELECT * FROM users WHERE username = ?1 LIMIT 1",
        [username],
        row_to_user,
    )
    .ok()
}

/// 按 id 查用户
pub fn user_by_id(db: &Db, id: i64) -> Option<User> {
    let conn = db.conn();
    conn.query_row("SELECT * FROM users WHERE id = ?1", [id], row_to_user)
        .ok()
}

pub fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        email: row.get(2)?,
        password: row.get(3)?,
        nickname: row.get(4)?,
        avatar: row.get(5)?,
        group_id: row.get(6)?,
        is_admin: row.get::<_, i64>(7)? != 0,
        status: row.get(8)?,
        remark: row.get(9)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(10)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(11)?),
    })
}
