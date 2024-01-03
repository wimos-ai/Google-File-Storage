use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const NONCE_SIZE: usize = 12;

/// TODO: Go in blocks

pub fn encrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) {
    let mut file_in = File::open(input_file).expect("Failed to open input file");
    let mut file_out = File::create(output_file).expect("Failed to open output file");

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let mut encryptor = Aes256Gcm::new(&key);

    let mut file_bytes = vec![0;file_in.metadata().unwrap().len() as usize];
    file_in.read(file_bytes.as_mut_slice()).expect("Could not read file bytes");

    let enc_bytes = encryptor.encrypt(&nonce,file_bytes.as_ref()).expect("Could not encrypt file");

    file_out.write(&nonce).expect("Could not write Nonce");
    file_out.write(&enc_bytes).expect("Could not write enc bytes");

}

pub fn decrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) {
    let mut file_in = File::open(input_file).expect("Failed to open input file");
    let mut file_out = File::create(output_file).expect("Failed to open output file");

    let mut file_bytes = vec![0;file_in.metadata().unwrap().len() as usize];
    file_in.read(file_bytes.as_mut_slice()).expect("Could not read file bytes");

    let nonce = Nonce::from_slice(&file_bytes[0..NONCE_SIZE]);
    let mut encryptor = Aes256Gcm::new(&key);

    let denc_bytes = encryptor.decrypt(&nonce,&file_bytes[NONCE_SIZE..]).expect("Could not encrypt file");

    file_out.write(&denc_bytes).expect("Could not write enc bytes");

}
