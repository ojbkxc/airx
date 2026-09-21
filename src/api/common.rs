//! 响应封装（对齐 Go http/response/response.go）
//!
//! 消息翻译：Go 每个控制器调 response.Fail(c, code, TranslateMsg(c, "Key"))，
//! Rust 侧把翻译下沉到 fail()/error() 内部——调用点仍传键名，响应对齐 Go。

use axum::Json;
use serde_json::{json, Value};

use crate::i18n;

/// 从请求头解析语言并翻译消息键（Accept-Language 缺省 → en）
pub fn tr(headers: &axum::http::HeaderMap, key: &str) -> String {
    let lang = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .map(i18n::lang_from_accept_language)
        .unwrap_or("en");
    i18n::translate(lang, key)
}

/// 成功响应 {code:0, message, data}
pub fn success(data: Value) -> Json<Value> {
    Json(json!({
        "code": 0,
        "message": "success",
        "data": data,
    }))
}

/// 失败响应 {code, message, data:null}（Go Response.Data 无 omitempty）。
/// message 保持原样（调用点若要 i18n 翻译用 fail_h）
pub fn fail(code: i64, message: &str) -> Json<Value> {
    Json(json!({
        "code": code,
        "message": message,
        "data": Value::Null,
    }))
}

/// 失败响应（带请求头 → i18n 翻译；对齐 Go response.Fail(c, code, TranslateMsg(c, key))）
pub fn fail_h(code: i64, key: &str, headers: &axum::http::HeaderMap) -> Json<Value> {
    Json(json!({
        "code": code,
        "message": tr(headers, key),
        "data": Value::Null,
    }))
}

/// 失败响应（动态 message）
pub fn fail_msg(code: i64, message: String) -> Json<Value> {
    Json(json!({
        "code": code,
        "message": message,
        "data": Value::Null,
    }))
}

/// 错误响应 {error}（HTTP 400，对齐 Go response.Error）
pub fn error(message: &str) -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": message })),
    )
}

/// 错误响应（带请求头 → i18n 翻译；对齐 Go response.Error(c, TranslateMsg(c, key))）
pub fn error_h(
    key: &str,
    headers: &axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": tr(headers, key) })),
    )
}

/// 客户端 401 {error: "Unauthorized"}
pub fn unauthorized() -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Unauthorized" })),
    )
}

/// 后台分页 {page, total, list}（对齐 PageData）
pub fn page_data(page: i64, total: i64, list: Value) -> Json<Value> {
    Json(json!({
        "page": page,
        "total": total,
        "list": list,
    }))
}

/// 客户端分页 {total, data}（对齐 DataResponse）
pub fn data_response(total: i64, data: Value) -> Json<Value> {
    Json(json!({
        "total": total,
        "data": data,
    }))
}
