use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Form, Router,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;

mod db;
mod models;
mod schema;

const CONFIG_FILENAME: &str = "config.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerSettings {
    pub sdm_meta_read_key: String,
    pub sdm_file_read_key: String,
    pub cmac_input_format: String,
    pub public_key: String,
}

fn formatter(input_string: &str, picc_data: &str, enc_data: &str) -> String {
    input_string
        .replace("ENCPiccData", picc_data)
        .replace("SDMEncFileData", enc_data)
}

fn verify_signature(uid: &str, signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let key = VerifyingKey::from_bytes(public_key).unwrap();
    let sig = Signature::from_bytes(signature);

    if let Ok(_) = key.verify(&<[u8; 7]>::from_hex(uid).unwrap(), &sig) {
        return true;
    } else {
        return false;
    }
}

async fn ntag_handler(
    State(server_settings): State<ServerSettings>,
    Form(sdmdata): Form<sdm::SdmData>,
) -> Response {
    let s = sdm::Sdm::new(
        &server_settings.sdm_meta_read_key,
        &server_settings.sdm_file_read_key,
        sdmdata.clone(),
    );

    let verified = s.verify(&formatter(
        &server_settings.cmac_input_format,
        &sdmdata.e,
        &sdmdata.m,
    ));

    let signature_verification = verify_signature(
        &s.picc_data.uid,
        s.decrypt_message().unwrap().as_slice().try_into().unwrap(),
        &<[u8; 32]>::from_hex(server_settings.public_key.as_bytes()).unwrap(),
    );

    if verified && signature_verification {
        if let Err(e) = db::Db::new().register_card(&s.picc_data.uid, s.picc_data.read_counter as i32) {
            e.into_response()
        } else {
            "Access granted".into_response()
        }
    } else {
        "Card verification failed".into_response()
    }
}

#[tokio::main]
async fn main() {
    let server_settings: ServerSettings = serde_json::from_str(
        &fs::read_to_string(CONFIG_FILENAME).expect("Failed to open config file"),
    )
    .expect("Failed to parse server settings");

    let app = Router::new()
        .route("/", get(ntag_handler))
        .with_state(server_settings);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
