//! 静态文件服务：照抄 AIGX src/web/mod.rs（ServeDir + SPA fallback）

use std::convert::Infallible;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use tower_http::services::ServeDir;

pub fn serve_static_files() -> Router {
    let static_dir = find_static_dir().unwrap_or_else(|| PathBuf::from("static"));
    tracing::info!("Serving static files from: {:?}", static_dir);

    let index_path = static_dir.join("index.html");

    Router::new().fallback_service(ServeDir::new(&static_dir).fallback(tower::service_fn(
        move |_req: Request<Body>| {
            let index_path = index_path.clone();
            async move {
                let result: Result<Response<Body>, Infallible> =
                    match tokio::fs::read_to_string(&index_path).await {
                        Ok(content) => Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Body::from(content))
                            .unwrap_or_else(|_| {
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Internal Server Error"))
                                    .unwrap_or_else(|_| {
                                        Response::new(Body::from("Internal Server Error"))
                                    })
                            })),
                        Err(_) => Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::from("Not Found"))
                            .unwrap_or_else(|_| Response::new(Body::from("Not Found")))),
                    };
                result
            }
        },
    )))
}

/// 查找静态文件目录（照抄 AIGX 多候选探测）
fn find_static_dir() -> Option<PathBuf> {
    let candidates: Vec<Option<PathBuf>> = vec![
        Some(PathBuf::from(".").join("static")),
        Some(PathBuf::from(".").join("frontend").join("dist")),
        Some(PathBuf::from(".").join("admin").join("dist")),
        Some(PathBuf::from(".").join("web").join("static")),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .map(|p| p.join("static")),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .map(|p| p.join("..").join("static")),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.exists() && candidate.is_dir())
}
