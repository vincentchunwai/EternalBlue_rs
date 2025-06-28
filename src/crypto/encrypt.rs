use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

const ENCRYPTED_FILE_EXT: &str = ".cry";

fn encryptFile(input_file: &str, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_file)?;

    let cipher = Aes256Gcm::new(key.into());


    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    let output_file = format!("{}.{}", input_file, ENCRYPTED_FILE_EXT);
    let mut file = File::create(&output_file)?;

    file.write_all(&nonce)?;
    file.write_all(&ciphertext)?;

    println!("File encrypted successfully: {}", output_file);
    Ok(())
}

fn addEncryptedFileExtension(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {

    let dir = Path::new(file_path).parent().ok_or("Invalid file path")?;

    let base_name = Path::new(file_path).file_stem()
        .ok_or("Invalid file name")?
        .to_str()
        .ok_or("Invalid file name encoding")?;

    let new_file_name = format!("{}.{}", base_name, ENCRYPTED_FILE_EXT);
    let new_file_path = dir.join(new_file_name);

    fs::rename(file_path, &new_file_path)
        .map_err(|e| format!("Failed to rename file: {}", e))?;

    println!("File renamed to: {}", new_file_path.display());
    Ok(())
}