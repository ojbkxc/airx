//! 工具函数：bcrypt 密码 / MD5 / 时间格式化 / 客户端 IP 提取

use rand::distributions::Alphanumeric;
use rand::Rng;

/// bcrypt 哈希（cost = 10，对齐 Go bcrypt.DefaultCost）
pub fn hash_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap_or_default()
}

/// 校验密码。兼容 legacy MD5 哈希（自动升级为 bcrypt）。
/// 返回 (ok, new_hash)。
pub fn verify_password(hash: &str, password: &str) -> (bool, Option<String>) {
    match bcrypt::verify(password, hash) {
        Ok(true) => (true, None),
        _ => {
            // 尝试 legacy MD5（md5(password + "rustdesk-api")）
            let legacy = format!(
                "{:x}",
                md5::compute(format!("{}{}", password, "rustdesk-api"))
            );
            if hash == legacy {
                let new_hash = hash_password(password);
                (true, Some(new_hash))
            } else {
                (false, None)
            }
        }
    }
}

/// 生成随机 token（md5 风格，对齐 Go utils.Md5(username + time)）
pub fn generate_token(username: &str) -> String {
    let salt: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    format!(
        "{:x}",
        md5::compute(format!(
            "{}{}:{}",
            username,
            chrono::Utc::now().timestamp(),
            salt
        ))
    )
}

/// 生成随机密码（首次初始化 admin 用）
pub fn random_password(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// 解析客户端 IP：优先 X-Forwarded-For / X-Real-IP，回退 ConnectionInfo 对端。
pub fn client_ip(headers: &axum::http::HeaderMap, fallback: &str) -> String {
    if let Some(v) = headers.get("x-forwarded-for") {
        if let Ok(s) = v.to_str() {
            if let Some(first) = s.split(',').next() {
                let t = first.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip") {
        if let Ok(s) = v.to_str() {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    fallback.to_string()
}

/// float 转字符串去尾零（对齐 Go 对 session_id 的处理）
pub fn float_to_string(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

/// base64 编码（标准字母表，无填充差异由 base64 crate 处理）
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
