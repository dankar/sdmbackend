use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Form, Router,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;

const CONFIG_FILENAME: &str = "config.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerSettings {
    pub sdm_meta_read_key: String,
    pub sdm_file_read_key: String,
    pub cmac_input_format: String,
}

fn formatter(input_string: &str, picc_data: &str, enc_data: &str) -> String {
    input_string
        .replace("ENCPiccData", picc_data)
        .replace("SDMEncFileData", enc_data)
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

    if !verified {
        "Invalid tag".into_response()
    } else {
        format!(
            "Got a valid tag:\n{:#?}\nEncrypted message: {}",
            s.picc_data,
            String::from_utf8(s.decrypt_message().unwrap()).unwrap()
        )
        .into_response()
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
