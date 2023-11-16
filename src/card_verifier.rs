use crate::db;
use crate::server_settings::ServerSettings;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex::FromHex;
use log::info;

fn formatter(input_string: &str, picc_data: &str, enc_data: &str) -> String {
    input_string
        .replace("ENCPiccData", picc_data)
        .replace("SDMEncFileData", enc_data)
}

fn verify_card_signature(uid: &str, signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let key = VerifyingKey::from_bytes(public_key).unwrap();
    let sig = Signature::from_bytes(signature);

    if let Ok(_) = key.verify(&<[u8; 7]>::from_hex(uid).unwrap(), &sig) {
        return true;
    } else {
        return false;
    }
}

pub fn verify_card(server_settings: &ServerSettings, sdmdata: &sdm::SdmData) -> Result<(), String> {
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

    let decrypted_message = match s.decrypt_message() {
        Ok(v) => v,
        Err(()) => return Err("Failed to decrypt message".into()),
    };

    let signature_verification = verify_card_signature(
        &s.picc_data.uid,
        decrypted_message.as_slice().try_into().unwrap(),
        &<[u8; 32]>::from_hex(server_settings.public_key.as_bytes()).unwrap(),
    );

    info!(
        "Signature status: {:?}, CMAC status: {:?}",
        signature_verification, verified
    );

    if verified && signature_verification {
        match db::Db::new().register_card(&s.picc_data.uid, s.picc_data.read_counter as i32) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        return Err("Card verification failed".into());
    }
}
