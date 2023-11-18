use axum::{
    body::{boxed, Body, BoxBody},
    http::{Request, StatusCode, Uri},
    response::Response, extract::State,
};
use tower::ServiceExt;
use tower_http::services::ServeDir;


pub async fn static_handler(State(redirect): State<String>, uri: Uri) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();

    match ServeDir::new(&redirect).oneshot(req).await {
        Ok(res) => Ok(res.map(boxed)),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("500: {}", err),
        )),
    }
}
