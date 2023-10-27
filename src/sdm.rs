use aes::cipher::{
    generic_array::{typenum::*, GenericArray},
    BlockDecrypt, KeyInit,
};
use aes::Aes128;
use cmac::{Cmac, Mac};

use hex::FromHex;

#[derive(Debug)]
pub struct PiccData {
    pub tag_data: u8,
    pub uid: String,
    pub read_counter: u32,
}

pub fn decrypt_picc_data(sdm_meta_read_key: &str, enc_picc_data: &str) -> Option<PiccData> {
    if sdm_meta_read_key.len() != 32 {
        return None;
    }

    if enc_picc_data.len() != 32 {
        return None;
    }

    let key: GenericArray<_, U16> =
        GenericArray::clone_from_slice(&<[u8; 16]>::from_hex(sdm_meta_read_key).unwrap());
    let mut block: GenericArray<_, U16> =
        GenericArray::clone_from_slice(&<[u8; 16]>::from_hex(enc_picc_data).unwrap());

    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut block);

    let result = PiccData {
        tag_data: block[0],
        uid: block[1..8]
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(""),
        read_counter: block[8..11]
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, x)| acc + ((*x as u32) << (i * 8))),
    };

    return Some(result);
}

pub fn verify_mac(sdm_file_read_mac: &str, picc_data: &PiccData, mac: &str) -> bool {
    let key: GenericArray<_, U16> =
        GenericArray::clone_from_slice(&<[u8; 16]>::from_hex(sdm_file_read_mac).unwrap());
    let mut uid_vec = Vec::from(<[u8; 7]>::from_hex(&picc_data.uid).unwrap());
    let mut sv2 = vec![0x3Cu8, 0xC3, 0x00, 0x01, 0x00, 0x80];
    sv2.append(&mut uid_vec);
    sv2.append(&mut vec![
        (picc_data.read_counter & 0xff) as u8,
        ((picc_data.read_counter >> 8) & 0xff) as u8,
        ((picc_data.read_counter >> 16) & 0xff) as u8,
    ]);

    let sv2_array: GenericArray<_, U16> = GenericArray::clone_from_slice(&sv2);

    let mut mac_cipher = <Cmac<Aes128> as KeyInit>::new(&key);
    mac_cipher.update(&sv2_array);
    let result = mac_cipher.finalize();
    let session_key = result.into_bytes();

    let mac_cipher = <Cmac<Aes128> as KeyInit>::new(&session_key);
    let result = mac_cipher.finalize();
    let mac_result = result.into_bytes();

    if mac_result
        .iter()
        .skip(1)
        .step_by(2)
        .map(|x| format!("{:02X}", x))
        .collect::<Vec<String>>()
        .join("")
        == mac
    {
        return true;
    } else {
        return false;
    }
}
