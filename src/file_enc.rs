use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key, AeadInPlace};

use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::ptr::write;
use aes_gcm::aes::Aes256;

/*

const BLOCK_SIZE: usize = 1024;
const NONCE_SIZE: u64 = 12;

pub fn encrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) {
    let mut file_in = File::open(input_file).expect("Failed to open input file");
    let mut file_out = File::create(output_file).expect("Failed to open output file");

    let mut file_size = file_in.metadata().unwrap().len() as usize;

    let mut tmp_buff: Vec<u8> = vec![0; BLOCK_SIZE];

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let mut encryptor = Aes256Gcm::new(&key);

    file_out.write_all(nonce.as_slice()).expect("Failed writing nonce");

    let num_blocks: usize = file_size / BLOCK_SIZE;

    for _ in 0..num_blocks {
        file_in.read_exact(tmp_buff.as_mut_slice()).expect("Failed To Read Blocksize");
        let enc_bytes = encryptor.encrypt(&nonce, tmp_buff.as_ref()).expect("Encryption Error");
        file_out.write_all(enc_bytes.as_slice()).expect("File did not write");
        file_size -= BLOCK_SIZE;
    }

    tmp_buff.resize(file_size, 0);

    file_in.read_exact(tmp_buff.as_mut_slice()).expect("Failed to read remaining bytes");
    let enc_bytes = encryptor.encrypt(&nonce, tmp_buff.as_ref()).expect("Encryption Error");
    file_out.write_all(enc_bytes.as_slice()).expect("File did not write");
}

pub fn decrypt_file(input_file: &Path, output_file: &Path, key: &Key<Aes256Gcm>) {
    let mut file_in = File::open(input_file).expect("Failed to open input file");
    let mut file_out = File::create(output_file).expect("Failed to open output file");

    let mut file_size = (file_in.metadata().unwrap().len() - NONCE_SIZE) as usize;

    let mut tmp_buff: Vec<u8> = vec![0; BLOCK_SIZE as usize];

    let mut nonce = vec![0; NONCE_SIZE as usize]; // 96-bits; unique per message
    file_in.read_exact(nonce.as_mut_slice()).expect("Failed to read nonce");
    let nonce = Nonce::from_slice(nonce.as_slice());

    let mut encryptor = Aes256Gcm::new(&key);

    loop {
        if file_size >= BLOCK_SIZE {
            file_in.read_exact(tmp_buff.as_mut_slice()).expect("Failed To Read Blocksize");
            file_size -= BLOCK_SIZE;
        } else {
            tmp_buff.resize(file_size as usize, 0);
            file_in.read_exact(tmp_buff.as_mut_slice()).expect("Failed To Read Blocksize");
            file_size = 0;
        }

        let enc_bytes = encryptor.decrypt(&nonce, tmp_buff.as_ref()).expect("Decryption Error");
        file_out.write_all(enc_bytes.as_slice()).expect("File did not write");

        if file_size <= 0 {
            break;
        }
    }
}
 */

const NONCE_SIZE: usize = 12;

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

    let denc_bytes = encryptor.encrypt(&nonce,&file_bytes[NONCE_SIZE..]).expect("Could not encrypt file");

    file_out.write(&denc_bytes).expect("Could not write enc bytes");

}
