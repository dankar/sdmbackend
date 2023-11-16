mod card_verifier;
mod db;
mod models;
mod schema;
mod server_settings;

use crate::server_settings::ServerSettings;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Form, Router,
};
use axum_session::{
    Key, SecurityMode, Session, SessionConfig, SessionLayer, SessionNullPool, SessionStore,
};
use dotenvy::dotenv;
use log::info;
use simple_logger::SimpleLogger;
use std::net::SocketAddr;

const CONFIG_FILENAME: &str = "config.json";

async fn ntag_auth(
    session: Session<SessionNullPool>,
    State(server_settings): State<ServerSettings>,
    Form(sdmdata): Form<sdm::SdmData>,
) -> Result<Redirect, (StatusCode, Response)> {
    info!("Got NTAG request");

    match card_verifier::verify_card(&server_settings, &sdmdata) {
        Ok(()) => {
            session.set("auth", 1);
            Ok(Redirect::to("secret_stuff"))
        }
        Err(e) => Err((StatusCode::UNAUTHORIZED, e.into_response())),
    }
}

async fn secret_stuff(session: Session<SessionNullPool>) -> Result<Response, (StatusCode, Response)> {
    let auth = session.get("auth").unwrap_or(0);
    if auth == 1 {
        Ok("You're in!".into_response())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Nope".into_response()))
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    SimpleLogger::new().env().init().unwrap();

    let session_config = SessionConfig::default()
        .with_key(Key::generate())
        .with_security_mode(SecurityMode::PerSession);
    let session_store = SessionStore::<SessionNullPool>::new(None, session_config)
        .await
        .unwrap();

    let server_settings = server_settings::ServerSettings::new(CONFIG_FILENAME)
        .expect("Failed to parse server settings");

    let listen_port = server_settings.listen_port;

    let app = Router::new()
        .route("/", get(ntag_auth))
        .route("/secret_stuff", get(secret_stuff))
        .layer(SessionLayer::new(session_store))
        .with_state(server_settings);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .serve(app.into_make_service())
        .await
        .unwrap();
}
