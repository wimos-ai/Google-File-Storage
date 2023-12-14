mod file_enc;

use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read};

use aes_gcm::{
    Aes256Gcm, Key, // Or `Aes128Gcm`
};

fn is_same_file(file1: &Path, file2: &Path) -> Result<bool, std::io::Error> {
    let f1 = File::open(file1)?;
    let f2 = File::open(file2)?;

    // Check if file sizes are different
    if f1.metadata().unwrap().len() != f2.metadata().unwrap().len() {
        return Ok(false);
    }

    // Use buf readers since they are much faster
    let f1 = BufReader::new(f1);
    let f2 = BufReader::new(f2);

    // Do a byte to byte comparison of the two files
    for (b1, b2) in f1.bytes().zip(f2.bytes()) {
        if b1.unwrap() != b2.unwrap() {
            return Ok(false);
        }
    }

    return Ok(true);
}


fn main() {
    let k = Key::<Aes256Gcm>::from_slice("12345678901234567890123456789012".as_bytes());
    let input_file = Path::new("C:\\Users\\willm\\Desktop\\tmp.txt");
    assert!(is_same_file(input_file, input_file).unwrap());

    let enc_file = Path::new("C:\\Users\\willm\\Desktop\\tmp.txt.enc");
    let d_enc_file = Path::new("C:\\Users\\willm\\Desktop\\tmp.denc.txt");
    file_enc::encrypt_file(input_file, enc_file, &k);
    file_enc::decrypt_file(enc_file, d_enc_file, &k);
    print!("Hello World");
    assert!(is_same_file(input_file, d_enc_file).unwrap(), "Files Were not the same :(");
}
