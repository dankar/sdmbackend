use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerSettings {
    pub sdm_meta_read_key: String,
    pub sdm_file_read_key: String,
    pub cmac_input_format: String,
    pub public_key: String,
    pub secret_files: String,
    pub listen_port: u16,
}

impl ServerSettings {
    pub fn new(filepath: &str) -> Result<Self, String> {
        let file = match fs::read_to_string(filepath) {
            Ok(f) => f,
            Err(e) => return Err(e.to_string()),
        };

        match serde_json::from_str(&file) {
            Ok(obj) => Ok(obj),
            Err(e) => Err(e.to_string())
        }
    }
}
