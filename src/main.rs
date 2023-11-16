mod card_verifier;
mod db;
mod models;
mod schema;
mod server_settings;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Form, Router,
};
use dotenvy::dotenv;
use log::info;
use simple_logger::SimpleLogger;
use std::net::SocketAddr;
use crate::server_settings::ServerSettings;

const CONFIG_FILENAME: &str = "config.json";

async fn ntag_handler(
    State(server_settings): State<ServerSettings>,
    Form(sdmdata): Form<sdm::SdmData>,
) -> Response {
    info!("Got NTAG request");

    match card_verifier::verify_card(&server_settings, &sdmdata) {
        Ok(()) => "Access granted".into_response(),
        Err(e) => e.into_response(),
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    SimpleLogger::new().env().init().unwrap();

    let server_settings = server_settings::ServerSettings::new(CONFIG_FILENAME)
        .expect("Failed to parse server settings");

    let listen_port = server_settings.listen_port;

    let app = Router::new()
        .route("/", get(ntag_handler))
        .with_state(server_settings);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .serve(app.into_make_service())
        .await
        .unwrap();
}
