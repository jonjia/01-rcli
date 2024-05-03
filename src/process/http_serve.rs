use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{header::CONTENT_TYPE, Response, StatusCode},
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/", get(index_handler))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn index_handler() -> Response<String> {
    let html = format_dir_html(".").await;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html")
        .body(html)
        .unwrap()
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> Response<String> {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "text/plain")
            .body(format!("File {} not found", p.display()))
            .unwrap()
    } else if p.is_dir() {
        println!("Reading directory {:?}", p);
        // if it is a directory, list all files/subdirectories
        // as <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>
        let html = format_dir_html(p.to_str().unwrap()).await;
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/html")
            .body(html)
            .unwrap()
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(content)
                    .unwrap()
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(e.to_string())
                    .unwrap()
            }
        }
    }
}

async fn format_dir_html(dir: &str) -> String {
    let mut content = "<html><body><ul>".to_string();
    let mut children_dir = fs::read_dir(dir).await.unwrap();
    content.push_str(&format!(
        "<li><a href=\"/{}\">../</a></li>",
        std::path::Path::new(&dir)
            .join("../")
            .strip_prefix(".")
            .unwrap()
            .to_str()
            .unwrap()
    ));

    // 遍历目录的每一个条目
    while let Some(entry) = children_dir.next_entry().await.unwrap() {
        let file_name = entry.file_name();
        let file_path = entry.path();
        let file_path = file_path.strip_prefix(".").unwrap_or(&file_path);
        content.push_str(&format!(
            "<li><a href=\"/{}\">{}</a></li>",
            file_path.to_str().unwrap(),
            file_name.to_str().unwrap()
        ));
    }
    content.push_str("</ul></body></html>");
    content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let res = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.body().trim().starts_with("[package]"));
    }
}
