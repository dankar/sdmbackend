mod authentication;
mod card_verifier;
mod db;
mod handlers;
mod models;
mod schema;
mod server_settings;

use crate::server_settings::ServerSettings;
use axum::{middleware, routing::get, Router};
use axum_session::{Key, SecurityMode, SessionConfig, SessionLayer, SessionNullPool, SessionStore};
use dotenvy::dotenv;
use simple_logger::SimpleLogger;
use std::net::SocketAddr;

const CONFIG_FILENAME: &str = "config.json";

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

    let server_settings =
        ServerSettings::new(CONFIG_FILENAME).expect("Failed to parse server settings");

    let listen_port = server_settings.listen_port;

    let app = Router::new()
        .route("/", get(authentication::ntag_auth_handler))
        .route("/logout", get(authentication::ntag_logout))
        .nest_service(
            "/secret",
            get(handlers::static_handler).with_state(String::from("secret-static/"))
                .route_layer(middleware::from_fn(authentication::check_auth)),
        )
        .nest_service("/static", get(handlers::static_handler).with_state(String::from("static/")))
        .layer(SessionLayer::new(session_store))
        .with_state(server_settings);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .serve(app.into_make_service())
        .await
        .unwrap();
}
