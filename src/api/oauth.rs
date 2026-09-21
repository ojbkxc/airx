//! OAuth/OIDC + webauth（对齐 Go service/oauth.go + http/controller/api/ouath.go + admin/oauth.go）
//!
//! 授权流：
//! - BeginAuth：state=RandomString(10)+unix；webauth → `ApiServer + "/_admin/#/oauth/" + state`；
//!   github/linuxdo/oidc → AuthCodeURL（含 nonce、PKCE S256/plain），RedirectURL = `ApiServer + "/api/oidc/callback"`
//! - callback：code → token exchange（PKCE verifier）→ id_token nonce 校验（仅解析 claims，不验签——
//!   Go 侧 provider.Verifier 对 github/linuxdo 是空 JWKS 的伪 provider，等价于只解码）→ GET userinfo
//! - login：查 user_thirds（open_id+op）→ 无则 auto_register ? 注册 : 重定向 `/_admin/#/oauth/bind/{state}`
//! - bind：管理面 confirm/bindConfirm/unbind/info
//!
//! state 存内存 OauthCache（Mutex<HashMap> + 过期时间戳，对齐 Go sync.Map + time.AfterFunc）。

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::admin::AdminState;
use crate::models::User;

// ─────────────────────────── OauthCache ───────────────────────────

/// OAuth 缓存条目（对齐 Go service.OauthCacheItem）
#[derive(Clone, Debug, Default)]
pub struct OauthCacheItem {
    pub user_id: i64,
    pub id: String, // rustdesk 设备 ID
    pub op: String,
    pub action: String, // login / bind
    pub uuid: String,
    pub device_name: String,
    pub device_os: String,
    pub device_type: String,
    pub open_id: String,
    pub username: String,
    pub name: String,
    pub email: String,
    pub verifier: String, // PKCE
    pub nonce: String,
}

impl OauthCacheItem {
    pub fn to_json(&self) -> Value {
        json!({
            "user_id": self.user_id,
            "id": self.id,
            "op": self.op,
            "action": self.action,
            "uuid": self.uuid,
            "device_name": self.device_name,
            "device_os": self.device_os,
            "device_type": self.device_type,
            "open_id": self.open_id,
            "username": self.username,
            "name": self.name,
            "email": self.email,
        })
    }
}

/// 全局 OAuth 缓存（进程内；(item, expires_at_unix)）
static OAUTH_CACHE: Mutex<Option<HashMap<String, (OauthCacheItem, i64)>>> = Mutex::new(None);

fn cache_get(state: &str) -> Option<OauthCacheItem> {
    let mut g = OAUTH_CACHE.lock().unwrap();
    let map = g.as_mut()?;
    let (item, exp) = map.get(state)?;
    if *exp > crate::db::now_unix() || *exp == 0 {
        Some(item.clone())
    } else {
        map.remove(state);
        None
    }
}

fn cache_set(state: &str, item: OauthCacheItem, ttl_secs: i64) {
    let mut g = OAUTH_CACHE.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    let exp = if ttl_secs > 0 {
        crate::db::now_unix() + ttl_secs
    } else {
        0
    };
    map.insert(state.to_string(), (item, exp));
}

fn cache_delete(state: &str) {
    if let Some(map) = OAUTH_CACHE.lock().unwrap().as_mut() {
        map.remove(state);
    }
}

// ─────────────────────────── provider 配置 ───────────────────────────

/// OIDC discovery 结果（issuer/.well-known/openid-configuration）
#[derive(Debug, Clone, Default)]
pub struct OidcEndpoint {
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

/// 解析后的 OAuth provider 端点配置（对齐 Go GetOauthConfig 的 oauth2.Config + provider）
struct OauthProviderConfig {
    #[allow(dead_code)] // 对齐 Go 结构保留
    oauth_type: String,
    auth_url: String,
    token_url: String,
    userinfo_url: String,
    scopes: Vec<String>,
}

const USER_ENDPOINT_GITHUB: &str = "https://api.github.com/user";
const USER_ENDPOINT_LINUXDO: &str = "https://connect.linux.do/api/user";
const OIDC_DEFAULT_SCOPES: &str = "openid,profile,email";

fn construct_scopes(scopes: &str) -> Vec<String> {
    let s = scopes.trim();
    let s = if s.is_empty() { OIDC_DEFAULT_SCOPES } else { s };
    s.split(',').map(|v| v.trim().to_string()).collect()
}

/// 按 op 读取 oauths 表并构造端点配置（对齐 Go GetOauthConfig）
async fn get_oauth_config(
    state: &AdminState,
    op: &str,
) -> Result<(crate::models::Oauth, OauthProviderConfig), String> {
    let oauth_info = match oauth_by_op(&state.db, op) {
        Some(o) => o,
        None => return Err("ConfigNotFound".to_string()),
    };
    if oauth_info.id == 0 || oauth_info.client_id.is_empty() || oauth_info.client_secret.is_empty()
    {
        return Err("ConfigNotFound".to_string());
    }
    let cfg = match oauth_info.oauth_type.as_str() {
        "github" => OauthProviderConfig {
            oauth_type: "github".into(),
            auth_url: "https://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            userinfo_url: USER_ENDPOINT_GITHUB.into(),
            scopes: vec!["read:user".into(), "user:email".into()],
        },
        "linuxdo" => OauthProviderConfig {
            oauth_type: "linuxdo".into(),
            auth_url: "https://connect.linux.do/oauth2/authorize".into(),
            token_url: "https://connect.linux.do/oauth2/token".into(),
            userinfo_url: USER_ENDPOINT_LINUXDO.into(),
            scopes: vec!["profile".into()],
        },
        "oidc" | "google" => {
            // discovery: {issuer}/.well-known/openid-configuration
            let issuer = oauth_info.issuer.trim_end_matches('/');
            if issuer.is_empty() {
                return Err("ConfigNotFound".to_string());
            }
            let well_known = format!("{}/.well-known/openid-configuration", issuer);
            let ep = fetch_oidc_discovery(&well_known).await?;
            OauthProviderConfig {
                oauth_type: oauth_info.oauth_type.clone(),
                auth_url: ep.auth_url,
                token_url: ep.token_url,
                userinfo_url: ep.userinfo_url,
                scopes: construct_scopes(&oauth_info.scopes),
            }
        }
        _ => return Err("unsupported OAuth type".to_string()),
    };
    Ok((oauth_info, cfg))
}

/// OIDC discovery 请求
async fn fetch_oidc_discovery(url: &str) -> Result<OidcEndpoint, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("DiscoveryError: {}", e))?;
    let resp: Value = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("DiscoveryError: {}", e))?
        .json()
        .await
        .map_err(|e| format!("DiscoveryError: {}", e))?;
    Ok(OidcEndpoint {
        auth_url: resp
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        token_url: resp
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        userinfo_url: resp
            .get("userinfo_endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

// ─────────────────────────── BeginAuth ───────────────────────────

/// 对齐 Go utils.RandomString：字母表 a-zA-Z0-9
fn random_string(n: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// PKCE verifier：43 字节 URL-safe base64（32 octets，对齐 Go oauth2.GenerateVerifier）
fn generate_pkce_verifier() -> String {
    use base64::Engine;
    use rand::Rng;
    let mut data = [0u8; 32];
    rand::thread_rng().fill(&mut data);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// S256 challenge（base64url(sha256(verifier))）
fn s256_challenge(verifier: &str) -> String {
    use base64::Engine;
    let sha = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha)
}

/// 对齐 Go BeginAuth → (state, verifier, nonce, url)
async fn begin_auth(
    state: &AdminState,
    op: &str,
) -> Result<(String, String, String, String), String> {
    let state_code = format!("{}{}", random_string(10), crate::db::now_unix());
    let mut verifier = String::new();
    let mut nonce = String::new();
    if op == "webauth" {
        let cfg = state.config_manager.get().await;
        let url = format!("{}/_admin/#/oauth/{}", cfg.rustdesk.api_server, state_code);
        return Ok((state_code, verifier, nonce, url));
    }
    let (_info, cfg) = get_oauth_config(state, op).await?;
    nonce = random_string(10);
    let mut params: Vec<(String, String)> = vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), _info.client_id.clone()),
        (
            "redirect_uri".into(),
            format!(
                "{}/api/oidc/callback",
                state.config_manager.get().await.rustdesk.api_server
            ),
        ),
        ("scope".into(), cfg.scopes.join(" ")),
        ("state".into(), state_code.clone()),
        ("nonce".into(), nonce.clone()),
    ];
    if _info.pkce_enable {
        verifier = generate_pkce_verifier();
        match _info.pkce_method.as_str() {
            "S256" => {
                params.push(("code_challenge_method".into(), "S256".into()));
                params.push(("code_challenge".into(), s256_challenge(&verifier)));
            }
            "plain" => {
                params.push(("code_challenge_method".into(), "plain".into()));
                params.push(("code_challenge".into(), verifier.clone()));
            }
            _ => {}
        }
    }
    let sep = if cfg.auth_url.contains('?') { '&' } else { '?' };
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    Ok((
        state_code,
        verifier,
        nonce,
        format!("{}{}{}", cfg.auth_url, sep, query),
    ))
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ─────────────────────────── Callback（token exchange + userinfo） ───────────────────────────

/// 对齐 Go OauthUser
#[derive(Clone, Debug, Default)]
struct OauthUser {
    open_id: String,
    name: String,
    username: String,
    email: String,
    verified_email: bool,
    picture: String,
}

/// token exchange + 拉取 userinfo（对齐 Go callbackBase + 各 provider Callback）
async fn oauth_callback(
    state: &AdminState,
    code: &str,
    verifier: &str,
    op: &str,
    nonce: &str,
) -> Result<OauthUser, String> {
    let (info, cfg) = get_oauth_config(state, op).await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("GetOauthTokenError: {}", e))?;

    // ── token exchange（对齐 Go oauth2.Exchange：form-encoded POST）──
    let redirect = format!(
        "{}/api/oidc/callback",
        state.config_manager.get().await.rustdesk.api_server
    );
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.to_string()),
        ("redirect_uri".into(), redirect),
        ("client_id".into(), info.client_id.clone()),
        ("client_secret".into(), info.client_secret.clone()),
    ];
    if !verifier.is_empty() {
        form.push(("code_verifier".into(), verifier.to_string()));
    }
    let token_resp: Value = client
        .post(&cfg.token_url)
        .header(header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|_| "GetOauthTokenError".to_string())?
        .json()
        .await
        .map_err(|_| "GetOauthTokenError".to_string())?;
    let access_token = token_resp
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        return Err("GetOauthTokenError".to_string());
    }

    // ── id_token nonce 校验（github/linuxdo 无 id_token，跳过）──
    let raw_id_token = token_resp
        .get("id_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !raw_id_token.is_empty() && !nonce.is_empty() {
        // 解码 payload 段（Go provider.Verifier 对内置 github/linuxdo 伪 provider 无 JWKS，
        // oidc/google 的验签等价于信任 discovery 端点；这里校验 nonce 一致性）
        let payload_b64 = raw_id_token.split('.').nth(1).unwrap_or("");
        if let Some(claims) = decode_jwt_claims(payload_b64) {
            if claims.get("nonce").and_then(|v| v.as_str()) != Some(nonce) {
                return Err("NonceDoesNotMatch".to_string());
            }
        } else {
            return Err("IDTokenClaimsError".to_string());
        }
    }

    // ── GET userinfo ──
    let user_resp: Value = client
        .get(&cfg.userinfo_url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await
        .map_err(|_| "GetOauthUserInfoError".to_string())?
        .json()
        .await
        .map_err(|_| "DecodeOauthUserInfoError".to_string())?;

    // ── 按 oauth_type 转换（对齐 Go GithubUser/LinuxdoUser/OidcUser.ToOauthUser）──
    let user = match info.oauth_type.as_str() {
        "github" => {
            let mut u = OauthUser {
                open_id: user_resp
                    .get("id")
                    .map(|v| v.to_string().trim_matches('"').to_string())
                    .unwrap_or_default(),
                name: user_resp
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                username: user_resp
                    .get("login")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase(),
                email: user_resp
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                picture: user_resp
                    .get("avatar_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                verified_email: false,
            };
            // github 还要拉 primary email（对齐 Go getGithubPrimaryEmail）
            if u.email.is_empty() {
                let emails: Value = client
                    .get("https://api.github.com/user/emails")
                    .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
                    .send()
                    .await
                    .map_err(|_| "GetOauthUserInfoError".to_string())?
                    .json()
                    .await
                    .unwrap_or(Value::Array(vec![]));
                if let Some(arr) = emails.as_array() {
                    for e in arr {
                        if e.get("primary").and_then(|v| v.as_bool()) == Some(true)
                            && e.get("verified").and_then(|v| v.as_bool()) == Some(true)
                        {
                            u.email = e
                                .get("email")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            u.verified_email = true;
                            break;
                        }
                    }
                }
            }
            u
        }
        "linuxdo" => OauthUser {
            open_id: user_resp
                .get("id")
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_default(),
            name: user_resp
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            username: user_resp
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase(),
            email: user_resp
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            verified_email: true, // linux.do 用户邮箱默认已验证
            picture: user_resp
                .get("avatar_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        },
        // oidc / google
        _ => {
            let preferred = user_resp
                .get("preferred_username")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let email = user_resp
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            OauthUser {
                open_id: user_resp
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: user_resp
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                username: if preferred.is_empty() {
                    email.to_lowercase()
                } else {
                    preferred.to_string()
                },
                email: email.to_string(),
                verified_email: user_resp
                    .get("email_verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                picture: user_resp
                    .get("picture")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        }
    };
    if user.open_id.is_empty() {
        return Err("DecodeOauthUserInfoError".to_string());
    }
    Ok(user)
}

/// 解码 JWT payload（base64url JSON）
fn decode_jwt_claims(b64: &str) -> Option<Value> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ─────────────────────────── user_thirds 辅助 ───────────────────────────

fn oauth_by_op(db: &crate::db::Db, op: &str) -> Option<crate::models::Oauth> {
    let conn = db.conn();
    conn.query_row(
        "SELECT id, op, oauth_type, client_id, client_secret, auto_register, scopes, issuer, pkce_enable, pkce_method, created_at, updated_at FROM oauths WHERE op = ?1 LIMIT 1",
        [op],
        crate::api::crud::row_to_oauth,
    )
    .ok()
}

/// 按 open_id + op 查 user_thirds（对齐 Go UserThirdInfo）
fn user_third_by_open_id(
    db: &crate::db::Db,
    op: &str,
    open_id: &str,
) -> Option<crate::models::UserThird> {
    let conn = db.conn();
    conn.query_row(
        "SELECT id, user_id, open_id, name, username, email, verified_email, picture, union_id, third_type, oauth_type, op, created_at, updated_at FROM user_thirds WHERE open_id = ?1 AND op = ?2 LIMIT 1",
        rusqlite::params![open_id, op],
        row_to_user_third,
    )
    .ok()
}

/// 按 user_id + op 查 user_thirds（对齐 Go UserService.UserThirdInfo）
fn user_third_by_user_id(
    db: &crate::db::Db,
    user_id: i64,
    op: &str,
) -> Option<crate::models::UserThird> {
    let conn = db.conn();
    conn.query_row(
        "SELECT id, user_id, open_id, name, username, email, verified_email, picture, union_id, third_type, oauth_type, op, created_at, updated_at FROM user_thirds WHERE user_id = ?1 AND op = ?2 LIMIT 1",
        rusqlite::params![user_id, op],
        row_to_user_third,
    )
    .ok()
}

fn row_to_user_third(row: &rusqlite::Row) -> rusqlite::Result<crate::models::UserThird> {
    Ok(crate::models::UserThird {
        id: row.get(0)?,
        user_id: row.get(1)?,
        open_id: row.get(2)?,
        name: row.get(3)?,
        username: row.get(4)?,
        email: row.get(5)?,
        verified_email: row.get::<_, i64>(6)? != 0,
        picture: row.get(7)?,
        union_id: row.get(8)?,
        third_type: row.get(9)?,
        oauth_type: row.get(10)?,
        op: row.get(11)?,
        created_at: crate::db::format_autotime(&row.get::<_, String>(12)?),
        updated_at: crate::db::format_autotime(&row.get::<_, String>(13)?),
    })
}

/// 绑定第三方账号（对齐 Go BindOauthUser → UserThird.FromOauthUser + Create）
fn bind_oauth_user(
    db: &crate::db::Db,
    user_id: i64,
    u: &OauthUser,
    oauth_type: &str,
    op: &str,
) -> Result<(), String> {
    let conn = db.conn();
    let res = conn.execute(
        "INSERT INTO user_thirds (user_id, open_id, name, username, email, verified_email, picture, union_id, third_type, oauth_type, op, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', ?8, ?9, datetime('now'), datetime('now'))",
        rusqlite::params![
            user_id,
            u.open_id,
            u.name,
            u.username,
            u.email.to_lowercase(),
            u.verified_email as i64,
            u.picture,
            oauth_type,
            op
        ],
    );
    res.map(|_| ()).map_err(|e| format!("BindFail: {}", e))
}

/// 解绑（对齐 Go UnBindOauthUser）
fn unbind_oauth_user(db: &crate::db::Db, user_id: i64, op: &str) -> Result<(), String> {
    let conn = db.conn();
    conn.execute(
        "DELETE FROM user_thirds WHERE user_id = ?1 AND op = ?2",
        rusqlite::params![user_id, op],
    )
    .map(|_| ())
    .map_err(|e| format!("OperationFailed: {}", e))
}

/// 按 oauth 查用户（对齐 Go InfoByOauthId）
fn user_by_oauth_id(db: &crate::db::Db, op: &str, open_id: &str) -> Option<User> {
    let ut = user_third_by_open_id(db, op, open_id)?;
    if ut.id == 0 {
        return None;
    }
    crate::api::admin::user_by_id(db, ut.user_id).filter(|u| u.id > 0)
}

/// OAuth 自动注册（对齐 Go RegisterByOauth：email 已注册则直接绑定；否则建新用户）
fn register_by_oauth(state: &AdminState, u: &OauthUser, op: &str) -> Result<User, String> {
    let oauth_info = oauth_by_op(&state.db, op).ok_or("ConfigNotFound")?;
    let oauth_type = oauth_info.oauth_type;

    // email 已注册 → 直接绑定该用户
    let email = u.email.trim().to_lowercase();
    if !email.is_empty() {
        let uid: Option<i64> = {
            let conn = state.db.conn();
            conn.query_row(
                "SELECT id FROM users WHERE email = ?1 LIMIT 1",
                [&email],
                |r| r.get(0),
            )
            .ok()
        };
        if let Some(uid) = uid {
            let _ = bind_oauth_user(&state.db, uid, u, &oauth_type, op);
            return crate::api::admin::user_by_id(&state.db, uid)
                .ok_or("OauthRegisterFailed".to_string());
        }
    }

    // 建新用户（对齐 Go GenerateUsernameByOauth：重名追加随机数字）
    let mut username = u.username.replace(' ', "").to_lowercase();
    if username.is_empty() {
        username = u.email.replace(' ', "").to_lowercase();
    }
    let new_uid: i64 = {
        let conn = state.db.conn();
        while conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username = ?1",
                [&username],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0
        {
            use rand::Rng;
            username.push((b'0' + rand::thread_rng().gen_range(0..10)) as char);
        }
        let res = conn.execute(
            "INSERT INTO users (username, email, password, nickname, avatar, group_id, is_admin, status, remark, created_at, updated_at)
             VALUES (?1, ?2, '', ?3, ?4, 1, 0, 1, '', datetime('now'), datetime('now'))",
            rusqlite::params![username, u.email.to_lowercase(), u.name, u.picture],
        );
        if res.is_err() {
            return Err("OauthRegisterFailed".to_string());
        }
        let uid = conn.last_insert_rowid();
        let _ = conn.execute(
            "INSERT INTO user_thirds (user_id, open_id, name, username, email, verified_email, picture, union_id, third_type, oauth_type, op, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', ?8, ?9, datetime('now'), datetime('now'))",
            rusqlite::params![
                uid,
                u.open_id,
                u.name,
                u.username,
                u.email.to_lowercase(),
                u.verified_email as i64,
                u.picture,
                oauth_type,
                op
            ],
        );
        uid
    };
    crate::api::admin::user_by_id(&state.db, new_uid)
        .filter(|x| x.id > 0)
        .ok_or("OauthRegisterFailed".to_string())
}

// ─────────────────────────── HTML 响应（对齐 Go oauth_fail/success.html） ───────────────────────────

fn oauth_html(title: &str, message: &str, success: bool) -> Response {
    let (color, icon) = if success {
        ("#4CAF50", "✓")
    } else {
        ("#ba363a", "⚠")
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} - AIRX API</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background-color: #f5f5f5; margin: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
.success-container {{ text-align: center; background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 90%; }}
.checkmark {{ color: {color}; font-size: 4rem; margin-bottom: 1rem; }}
h1 {{ color: #333; margin-bottom: 1rem; }}
p {{ color: #666; line-height: 1.6; margin-bottom: 1.5rem; }}
.return-link {{ display: inline-block; padding: 10px 20px; background-color: {color}; color: white; text-decoration: none; border-radius: 5px; }}
</style>
</head>
<body>
<div class="success-container">
<div class="checkmark">{icon}</div>
<h1>{title}</h1>
<p>{message}</p>
<a href="javascript:window.close()" class="return-link">Close</a>
</div>
</body>
</html>"#,
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

fn oauth_fail(message: &str) -> Response {
    oauth_html("OauthFailed", message, false)
}

fn oauth_success(message: &str) -> Response {
    oauth_html("OauthSuccess", message, true)
}

// ─────────────────────────── 管理面 OIDC（/api/admin/oidc/*） ───────────────────────────

/// POST /api/admin/oidc/auth（对齐 Go admin.Login.OidcAuth）
pub async fn handle_admin_oidc_auth(
    State(state): State<AdminState>,
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
    let (state_code, verifier, nonce, url) = match begin_auth(&state, &op).await {
        Ok(v) => v,
        Err(e) => return Err(crate::api::common::error(&e)),
    };
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
        device_name: body
            .get("deviceInfo")
            .and_then(|d| d.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uuid: body
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        verifier,
        nonce,
        ..Default::default()
    };
    cache_set(&state_code, item, 5 * 60);
    Ok(crate::api::common::success(
        json!({ "code": state_code, "url": url }),
    ))
}

/// GET /api/admin/oidc/auth-query（对齐 Go admin.Login.OidcAuthQuery → OidcAuthQueryPre → responseLoginSuccess）
pub async fn handle_admin_oidc_auth_query(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let code = q.get("code").cloned().unwrap_or_default();
    if code.is_empty() {
        return common_error_response_h("ParamsError", &headers);
    }
    let v = match cache_get(&code) {
        Some(v) => v,
        None => return common_error_response_h("OauthExpired", &headers),
    };
    // UserId 为 0 → 还在授权中（对齐 Go 1.4.2 webclient oidc fix）
    if v.user_id == 0 {
        return Json(json!({
            "message": "Authorization in progress, please login and bind",
            "error": "No authed oidc is found"
        }))
        .into_response();
    }
    let user = match crate::api::admin::user_by_id(&state.db, v.user_id) {
        Some(u) if u.id > 0 => u,
        _ => return common_error_response_h("UserNotFound", &headers),
    };
    cache_delete(&code);
    let ip = crate::utils::client_ip(&headers, "");
    let token = crate::api::admin::do_login(
        &state,
        &user,
        &crate::models::LoginLog {
            user_id: user.id,
            client: v.device_type.clone(),
            device_id: v.id.clone(),
            uuid: v.uuid.clone(),
            ip,
            type_: "oauth".to_string(),
            platform: v.device_os.clone(),
            ..Default::default()
        },
    );
    crate::api::admin::login_success_payload(&state, &user, &token).into_response()
}

fn common_error_response(msg: &str) -> Response {
    let (status, body) = crate::api::common::error(msg);
    (status, body).into_response()
}

/// 客户端 auth-query 错误（对齐 Go response.Error(c, TranslateMsg(c, key))）
fn common_error_response_h(msg: &str, headers: &HeaderMap) -> Response {
    let (status, body) = crate::api::common::error_h(msg, headers);
    (status, body).into_response()
}

// ─────────────────────────── 管理面 OAuth 绑定（/api/admin/oauth/*） ───────────────────────────

/// GET /api/admin/oauth/info（对齐 Go admin.Oauth.Info；需登录）
pub async fn handle_oauth_info(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) =
        match crate::auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
            Ok(v) => v,
            Err((code, msg)) => return crate::api::common::fail_h(code, msg, &headers),
        };
    let _ = user;
    let code = q.get("code").cloned().unwrap_or_default();
    if code.is_empty() {
        return crate::api::common::fail_h(101, "ParamsError", &headers);
    }
    match cache_get(&code) {
        Some(v) => crate::api::common::success(v.to_json()),
        None => crate::api::common::fail_h(101, "ItemNotFound", &headers),
    }
}

/// POST /api/admin/oauth/bind（对齐 Go admin.Oauth.ToBind）
pub async fn handle_oauth_bind(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let config = state.config_manager.get().await;
    let (user, _) =
        match crate::auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
            Ok(v) => v,
            Err((code, msg)) => {
                return crate::api::common::fail_h(code, msg, &headers).into_response()
            }
        };
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if op.is_empty() {
        return crate::api::common::fail_h(101, "ParamsError", &headers).into_response();
    }
    // 已绑定过 → 拒绝
    if let Some(ut) = user_third_by_user_id(&state.db, user.id, &op) {
        if ut.id > 0 {
            return crate::api::common::fail_h(101, "OauthHasBindOtherUser", &headers)
                .into_response();
        }
    }
    let (state_code, verifier, nonce, url) = match begin_auth(&state, &op).await {
        Ok(v) => v,
        Err(e) => return common_error_response(&e),
    };
    cache_set(
        &state_code,
        OauthCacheItem {
            action: "bind".to_string(),
            op,
            user_id: user.id,
            verifier,
            nonce,
            ..Default::default()
        },
        5 * 60,
    );
    crate::api::common::success(json!({ "code": state_code, "url": url })).into_response()
}

/// POST /api/admin/oauth/confirm（对齐 Go admin.Oauth.Confirm：确认授权登录）
pub async fn handle_oauth_confirm(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) =
        match crate::auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
            Ok(v) => v,
            Err((code, msg)) => return crate::api::common::fail_h(code, msg, &headers),
        };
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if code.is_empty() {
        return crate::api::common::fail_h(101, "ParamsError", &headers);
    }
    let mut v = match cache_get(&code) {
        Some(v) => v,
        None => return crate::api::common::fail_h(101, "OauthExpired", &headers),
    };
    v.user_id = user.id;
    cache_set(&code, v, 0);
    match cache_get(&code) {
        Some(v) => crate::api::common::success(v.to_json()),
        None => crate::api::common::fail_h(101, "OauthExpired", &headers),
    }
}

/// POST /api/admin/oauth/bindConfirm（对齐 Go admin.Oauth.BindConfirm）
pub async fn handle_oauth_bind_confirm(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) =
        match crate::auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
            Ok(v) => v,
            Err((code, msg)) => return crate::api::common::fail_h(code, msg, &headers),
        };
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if code.is_empty() {
        return crate::api::common::fail_h(101, "ParamsError", &headers);
    }
    let mut v = match cache_get(&code) {
        Some(v) => v,
        None => return crate::api::common::fail_h(101, "OauthExpired", &headers),
    };
    // 用缓存的 oauth 用户信息绑定（对齐 Go ToOauthUser → BindOauthUser）
    let ou = OauthUser {
        open_id: v.open_id.clone(),
        name: v.name.clone(),
        username: v.username.clone(),
        email: v.email.clone(),
        verified_email: false,
        picture: String::new(),
    };
    let oauth_type = oauth_by_op(&state.db, &v.op)
        .map(|o| o.oauth_type)
        .unwrap_or_default();
    if bind_oauth_user(&state.db, user.id, &ou, &oauth_type, &v.op).is_err() {
        return crate::api::common::fail_h(101, "BindFail", &headers);
    }
    v.user_id = user.id;
    let payload = v.to_json();
    cache_set(&code, v, 0);
    crate::api::common::success(payload)
}

/// POST /api/admin/oauth/unbind（对齐 Go admin.Oauth.Unbind）
pub async fn handle_oauth_unbind(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let config = state.config_manager.get().await;
    let (user, _) =
        match crate::auth::backend_user_auth(&state.db, &headers, config.app.token_expire_secs) {
            Ok(v) => v,
            Err((code, msg)) => return crate::api::common::fail_h(code, msg, &headers),
        };
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if op.is_empty() {
        return crate::api::common::fail_h(101, "ParamsError", &headers);
    }
    match user_third_by_user_id(&state.db, user.id, &op) {
        Some(ut) if ut.id > 0 => {}
        _ => return crate::api::common::fail_h(101, "ItemNotFound", &headers),
    }
    if unbind_oauth_user(&state.db, user.id, &op).is_err() {
        return crate::api::common::fail_h(101, "OperationFailed", &headers);
    }
    crate::api::common::success(Value::Null)
}

// ─────────────────────────── 客户端 OAuth/OIDC（/api/oidc/*、/api/oauth/*） ───────────────────────────

/// POST /api/oidc/auth（对齐 Go api.Oauth.OidcAuth）
pub async fn handle_oidc_auth(
    State(state): State<AdminState>,
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
    let (state_code, verifier, nonce, url) = match begin_auth(&state, &op).await {
        Ok(v) => v,
        Err(e) => return Err(crate::api::common::error(&e)),
    };
    let device_type = body
        .get("deviceInfo")
        .and_then(|d| d.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("app")
        .to_string();
    let item = OauthCacheItem {
        action: "login".to_string(),
        op: op.clone(),
        id: body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_type,
        device_os: body
            .get("deviceInfo")
            .and_then(|d| d.get("os"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_name: body
            .get("deviceInfo")
            .and_then(|d| d.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uuid: body
            .get("uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        verifier,
        nonce,
        ..Default::default()
    };
    cache_set(&state_code, item, 5 * 60);
    Ok(Json(json!({
        "code": state_code,
        "url": url,
    })))
}

/// GET /api/oidc/auth-query（对齐 Go api.Oauth.OidcAuthQuery → LoginRes）
pub async fn handle_oidc_auth_query(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let code = q.get("code").cloned().unwrap_or_default();
    if code.is_empty() {
        return common_error_response_h("ParamsError", &headers);
    }
    let v = match cache_get(&code) {
        Some(v) => v,
        None => return common_error_response_h("OauthExpired", &headers),
    };
    if v.user_id == 0 {
        return Json(json!({
            "message": "Authorization in progress, please login and bind",
            "error": "No authed oidc is found"
        }))
        .into_response();
    }
    let user = match crate::api::admin::user_by_id(&state.db, v.user_id) {
        Some(u) if u.id > 0 => u,
        _ => return common_error_response_h("UserNotFound", &headers),
    };
    cache_delete(&code);
    let ip = crate::utils::client_ip(&headers, "");
    let token = crate::api::admin::do_login(
        &state,
        &user,
        &crate::models::LoginLog {
            user_id: user.id,
            client: v.device_type.clone(),
            device_id: v.id.clone(),
            uuid: v.uuid.clone(),
            ip,
            type_: "oauth".to_string(),
            platform: v.device_os.clone(),
            ..Default::default()
        },
    );
    Json(json!({
        "access_token": token,
        "type": "access_token",
        "user": {
            "name": user.username,
            "email": user.email,
            "note": user.remark,
            "is_admin": user.is_admin,
            "status": user.status,
            "info": {},
        }
    }))
    .into_response()
}

/// GET /api/oauth/callback | /oauth/login | /oidc/callback | /oidc/login（对齐 Go OauthCallback）
pub async fn handle_oauth_callback(
    State(state): State<AdminState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let state_code = q.get("state").cloned().unwrap_or_default();
    if state_code.is_empty() {
        return oauth_fail("state is empty");
    }
    let oauth_cache = match cache_get(&state_code) {
        Some(v) => v,
        None => return oauth_fail("OauthExpired"),
    };
    let nonce = oauth_cache.nonce.clone();
    let op = oauth_cache.op.clone();
    let action = oauth_cache.action.clone();
    let verifier = oauth_cache.verifier.clone();
    let code = q.get("code").cloned().unwrap_or_default();

    // 换取用户信息
    let oauth_user = match oauth_callback(&state, &code, &verifier, &op, &nonce).await {
        Ok(u) => u,
        Err(e) => return oauth_fail(&e),
    };

    let user_id = oauth_cache.user_id;
    let openid = oauth_user.open_id.clone();

    if action == "bind" {
        // 检查此 openid 是否已绑定其他用户
        if let Some(ut) = user_third_by_open_id(&state.db, &op, &openid) {
            if ut.user_id > 0 {
                return oauth_fail("OauthHasBindOtherUser");
            }
        }
        let user = match crate::api::admin::user_by_id(&state.db, user_id) {
            Some(u) if u.id > 0 => u,
            _ => return oauth_fail("ItemNotFound"),
        };
        let oauth_type = oauth_by_op(&state.db, &op)
            .map(|o| o.oauth_type)
            .unwrap_or_default();
        if bind_oauth_user(&state.db, user.id, &oauth_user, &oauth_type, &op).is_err() {
            return oauth_fail("BindFail");
        }
        return oauth_success("BindSuccess");
    } else if action == "login" {
        if user_id != 0 {
            return oauth_fail("OauthHasBeenSuccess");
        }
        // 查绑定用户
        let user = match user_by_oauth_id(&state.db, &op, &openid) {
            Some(u) => Some(u),
            None => {
                let info = oauth_by_op(&state.db, &op);
                match info {
                    Some(info) if info.auto_register => {
                        match register_by_oauth(&state, &oauth_user, &op) {
                            Ok(u) => Some(u),
                            Err(e) => return oauth_fail(&e),
                        }
                    }
                    // 未绑定且不自动注册 → 缓存 oauth 用户信息，重定向到前端绑定页
                    _ => {
                        let mut updated = oauth_cache.clone();
                        updated.open_id = oauth_user.open_id.clone();
                        updated.username = oauth_user.username.clone();
                        updated.name = oauth_user.name.clone();
                        updated.email = oauth_user.email.clone();
                        cache_set(&state_code, updated, 5 * 60);
                        return axum::response::Redirect::temporary(&format!(
                            "/_admin/#/oauth/bind/{}",
                            state_code
                        ))
                        .into_response();
                    }
                }
            }
        };
        let user = match user {
            Some(u) if u.id > 0 => u,
            _ => return oauth_fail("OauthFailed"),
        };
        let mut updated = oauth_cache.clone();
        updated.user_id = user.id;
        cache_set(&state_code, updated, 0);
        // webadmin → 直接跳转后台首页
        if oauth_cache.device_type == "webadmin" {
            return axum::response::Redirect::temporary("/_admin/#/").into_response();
        }
        return oauth_success("OauthSuccess");
    }
    oauth_fail("ParamsError")
}

/// GET /api/oauth/msg | /oidc/msg（对齐 Go Oauth.Message：返回 JS 赋值片段）
pub async fn handle_oauth_msg(
    State(state): State<AdminState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let _ = state;
    let lang = q.get("lang").cloned().unwrap_or_default();
    let title_key = q.get("title").cloned().unwrap_or_default();
    let msg_key = q.get("msg").cloned().unwrap_or_default();
    let lang_tag = crate::i18n::lang_from_accept_language(&lang);
    let mut res = String::new();
    if !title_key.is_empty() {
        let t = crate::i18n::translate(lang_tag, &title_key);
        res.push_str(&format!(";title='{}';", t));
    }
    if !msg_key.is_empty() {
        let m = crate::i18n::translate(lang_tag, &msg_key);
        res.push_str(&format!("msg = '{}';", m));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        res,
    )
        .into_response()
}

// ─────────────────────────── provider 列表 ───────────────────────────

/// 查询 OAuth provider op 列表（对齐 Go OauthService.GetOauthProviders）
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
