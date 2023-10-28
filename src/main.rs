mod sdm;

use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Form, Router,
};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn ntag_handler(Form(sdmdata): Form<sdm::SdmData>) -> Response {
    let s = sdm::Sdm::new(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        sdmdata,
    );

    let verified = s.verify();

    if !verified {
        "Invalid tag".into_response()
    } else {
        format!(
            "Got a valid tag:\n{:#?}\nEncrypted message: {}",
            s.picc_data,
            String::from_utf8(s.decrypt_message()).unwrap()
        )
        .into_response()
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

    let app = Router::new().route("/", get(ntag_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
