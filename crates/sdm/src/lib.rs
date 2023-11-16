use aes::cipher::{
    generic_array::{typenum::*, GenericArray},
    BlockDecrypt, BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit,
};

use aes::Aes128;
use cmac::{Cmac, Mac};

use hex::FromHex;
use serde::Deserialize;
use log::debug;

#[derive(Debug)]
pub struct PiccData {
    pub tag_data: u8,
    pub uid: String,
    pub read_counter: u32,
}

#[derive(Deserialize, Clone)]
pub struct SdmData {
    pub e: String,
    pub m: String,
    pub c: String,
}

struct AsciiKeys {
    pub sdm_meta_read: String,
    pub sdm_file_read: String,
}

struct SdmKeys {
    sdm_meta_read: Vec<u8>,
    sdm_file_read: Vec<u8>,
}

impl TryFrom<&AsciiKeys> for SdmKeys {
    type Error = <[u8; 16] as FromHex>::Error;
    fn try_from(keys: &AsciiKeys) -> Result<Self, Self::Error> {
        Ok(SdmKeys {
            sdm_meta_read: Vec::from(<[u8; 16]>::from_hex(&keys.sdm_meta_read)?),
            sdm_file_read: Vec::from(<[u8; 16]>::from_hex(&keys.sdm_file_read)?),
        })
    }
}

pub struct Sdm {
    data: SdmData,
    pub picc_data: PiccData,
    session_key_enc: Vec<u8>,
    session_key_mac: Vec<u8>,
    ive: Vec<u8>,
}

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

impl Sdm {
    pub fn new(sdm_meta_read_key: &str, sdm_file_read_key: &str, data: SdmData) -> Self {
        let keys = SdmKeys::try_from(&AsciiKeys {
            sdm_meta_read: String::from(sdm_meta_read_key),
            sdm_file_read: String::from(sdm_file_read_key),
        })
        .unwrap();

        let picc_data = Self::decrypt_picc_data(&keys, &data.e).unwrap();

        let (session_key_enc, session_key_mac) = Self::calculate_session_keys(&keys, &picc_data);

        let mut ive_vec = vec![
            (picc_data.read_counter & 0xff) as u8,
            ((picc_data.read_counter >> 8) & 0xff) as u8,
            ((picc_data.read_counter >> 16) & 0xff) as u8,
        ];

        ive_vec.append(&mut vec![
            0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let mut ive = GenericArray::clone_from_slice(&ive_vec);

        Aes128::new(session_key_enc.as_slice().into()).encrypt_block(&mut ive);

        Self {
            data,
            picc_data,
            session_key_enc,
            session_key_mac,
            ive: ive.iter().cloned().collect(),
        }
    }

    fn calculate_session_keys(keys: &SdmKeys, picc_data: &PiccData) -> (Vec<u8>, Vec<u8>) {
        let uid_vec = Vec::from(<[u8; 7]>::from_hex(&picc_data.uid).unwrap());
        let read_ctr = vec![
            (picc_data.read_counter & 0xff) as u8,
            ((picc_data.read_counter >> 8) & 0xff) as u8,
            ((picc_data.read_counter >> 16) & 0xff) as u8,
        ];
        let mut sv1 = vec![0xc3u8, 0x3c, 0x00, 0x01, 0x00, 0x80];
        let mut sv2 = vec![0x3Cu8, 0xC3, 0x00, 0x01, 0x00, 0x80];
        sv1.append(&mut uid_vec.clone());
        sv1.append(&mut read_ctr.clone());
        sv2.append(&mut uid_vec.clone());
        sv2.append(&mut read_ctr.clone());

        let mut mac_cipher = <Cmac<Aes128> as KeyInit>::new(keys.sdm_file_read.as_slice().into());
        mac_cipher.update(&sv1);
        let result = mac_cipher.finalize();
        let session_key_enc = result.into_bytes();

        let mut mac_cipher = <Cmac<Aes128> as KeyInit>::new(keys.sdm_file_read.as_slice().into());
        mac_cipher.update(&sv2);
        let result = mac_cipher.finalize();
        let session_key_mac = result.into_bytes();

        return (
            session_key_enc.iter().cloned().collect(),
            session_key_mac.iter().cloned().collect(),
        );
    }

    fn decrypt_picc_data(keys: &SdmKeys, enc_picc_data: &str) -> Option<PiccData> {
        if enc_picc_data.len() != 32 {
            return None;
        }

        let mut block: GenericArray<_, U16> =
            GenericArray::clone_from_slice(&<[u8; 16]>::from_hex(enc_picc_data).unwrap());

        Aes128::new(keys.sdm_meta_read.as_slice().into()).decrypt_block(&mut block);

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

    pub fn verify(&self, cmac_input: &str) -> bool {
        let mut mac_cipher = <Cmac<Aes128> as KeyInit>::new(self.session_key_mac.as_slice().into());

        mac_cipher.update(cmac_input.as_bytes());
        let result = mac_cipher.finalize();
        let mac_result = result.into_bytes();

        let calc_mac = mac_result
            .iter()
            .skip(1)
            .step_by(2)
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<String>>()
                 .join("");

        debug!("Calculated cmac = {}", calc_mac);
        debug!("Expected cmac = {}", self.data.c);
        if calc_mac == self.data.c
        {
            return true;
        } else {
            return false;
        }
    }

    pub fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let mut raw_data = Vec::new();

        if self.data.m.len() % 32 != 0 {
            return Err(());
        }

        for sl in self.data.m.as_bytes().chunks(32) {
            raw_data.push(GenericArray::clone_from_slice(
                &<[u8; 16]>::from_hex(&sl).unwrap(),
            ));
        }
        
        Aes128CbcDec::new(
            self.session_key_enc.as_slice().into(),
            self.ive.as_slice().into(),
        )
        .decrypt_blocks_mut(&mut raw_data);

        return Ok(raw_data.iter().fold(Vec::new(), |mut acc, x| {
            acc.append(&mut x.iter().cloned().collect());
            acc
        }));
    }
}
