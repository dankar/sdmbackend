mod sdm;

use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Form, Router,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;
use serde::Deserialize;

#[derive(Deserialize)]
struct SdmData {
    e: String,
    c: String,
}

async fn ntag_handler(Form(sdmdata): Form<SdmData>) -> Response {
    let piccdata = match sdm::decrypt_picc_data("00000000000000000000000000000000", &sdmdata.e) {
        Some(e) => e,
        None => return "Invalid input data".into_response()
    };
    let verified = sdm::verify_mac("00000000000000000000000000000000", &piccdata, &sdmdata.c);

    if !verified {
        "Invalid tag".into_response()
    }
    else
    {
        format!("Got a valid tag: {:#?}", piccdata).into_response()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "example_parse_body_based_on_content_type=debug,tower_http=debug".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/", get(ntag_handler));
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
