mod file_enc;


use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read};

use aes_gcm::{Aes256Gcm, Key};

fn is_same_file(file1: &Path, file2: &Path) -> Result<bool, std::io::Error> {
    let f1 = File::open(file1)?;
    let f2 = File::open(file2)?;

    // Check if file sizes are different
    if f1.metadata()?.len() != f2.metadata()?.len() {
        return Ok(false);
    }

    // Use buf readers since they are much faster
    let f1 = BufReader::new(f1);
    let f2 = BufReader::new(f2);

    // Do a byte to byte comparison of the two files
    for (b1, b2) in f1.bytes().zip(f2.bytes()) {
        if b1? != b2? {
            return Ok(false);
        }
    }

    return Ok(true);
}


fn main() {
    let k = Key::<Aes256Gcm>::from_slice("12345678901234567890123456789012".as_bytes());

    let input_file = Path::new("C:\\Users\\willm\\RustroverProjects\\Google-File-Storage\\tmp.bin");
    let enc_file = Path::new("C:\\Users\\willm\\RustroverProjects\\Google-File-Storage\\tmp.bin.enc");
    let d_enc_file = Path::new("C:\\Users\\willm\\RustroverProjects\\Google-File-Storage\\tmp.denc.bin");

    file_enc::encrypt_file(input_file, enc_file, &k).expect("Could not encrypt file");
    file_enc::decrypt_file(enc_file, d_enc_file, &k).expect("Could not decrypt file");

    assert!(is_same_file(input_file, d_enc_file).unwrap(), "Files Were not the same :(");
}

