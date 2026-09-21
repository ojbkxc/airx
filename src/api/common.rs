//! 响应封装（对齐 Go http/response/response.go）

use axum::Json;
use serde_json::{json, Value};

/// 成功响应 {code:0, message, data}
pub fn success(data: Value) -> Json<Value> {
    Json(json!({
        "code": 0,
        "message": "success",
        "data": data,
    }))
}

/// 失败响应 {code, message, data:null}（Go Response.Data 无 omitempty）
pub fn fail(code: i64, message: &str) -> Json<Value> {
    Json(json!({
        "code": code,
        "message": message,
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
