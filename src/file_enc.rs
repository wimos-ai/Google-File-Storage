use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path};

const NONCE_SIZE: usize = 12;

/// TODO: Go in blocks

#[derive(Debug)]
pub enum FileEncError{
    IOError(std::io::Error),
    EncryptionError(aes_gcm::Error)
}

impl From<std::io::Error> for FileEncError {
    fn from(e: std::io::Error) -> Self {
        FileEncError::IOError(e)
    }
}

impl From<aes_gcm::Error> for FileEncError {
    fn from(e: aes_gcm::Error) -> Self {
        FileEncError::EncryptionError(e)
    }
}



pub fn encrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) -> Result<(), FileEncError> {
    let file_in = File::open(input_file)?;

    let mut file_out = File::create(output_file)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let encryptor = Aes256Gcm::new(&key);

    let file_bytes = vec![0; file_in.metadata()?.len() as usize];

    let enc_bytes = encryptor.encrypt(&nonce, file_bytes.as_ref())?;

    file_out.write(&nonce).expect("Could not write Nonce");
    file_out.write(&enc_bytes).expect("Could not write enc bytes");

    Ok(())
}

pub fn decrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) -> Result<(), FileEncError>{
    let mut file_in = File::open(input_file)?;
    let mut file_out = File::create(output_file)?;

    let mut file_bytes = vec![0; file_in.metadata()?.len() as usize];
    file_in.read(file_bytes.as_mut_slice())?;

    let nonce = Nonce::from_slice(&file_bytes[0..NONCE_SIZE]);
    let encryptor = Aes256Gcm::new(&key);

    let decrypted_bytes = encryptor.decrypt(&nonce, &file_bytes[NONCE_SIZE..])?;

    file_out.write(&decrypted_bytes)?;

    Ok(())
}
