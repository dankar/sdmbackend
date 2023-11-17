use axum::{
    body::{boxed, Body, BoxBody},
    response::Response,
    http::{StatusCode, Uri, Request}
};
use tower::ServiceExt;
use tower_http::services::ServeDir;

pub async fn secret_static_handler(uri: Uri) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let res = serve_static_file(uri.clone()).await?;

    if res.status() == StatusCode::NOT_FOUND {
        Err((StatusCode::NOT_FOUND, "404".into()))
    } else {
        Ok(res)
    }
}

async fn serve_static_file(uri: Uri) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();

    // `ServeDir` implements `tower::Service` so we can call it with `tower::ServiceExt::oneshot`
    match ServeDir::new("static/").oneshot(req).await {
        Ok(res) => Ok(res.map(boxed)),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", err),
        )),
    }
}
