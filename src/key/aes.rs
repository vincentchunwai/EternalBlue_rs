use rand::Rng;
use aes::Aes256;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::{RsaPublicKey, RsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use std::fs::File;
use std::io::{Write, Read};
use rsa::rand_core::OsRng;

pub const AES_ENCRPTED_KEY_PATH: &str = "encrypted_key.bin";

fn GenerateAesKey() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    
    let mut key = [0u8; 32];

    rand::thread_rng().fill(&mut key);
    Ok(key)
}

fn EncryptAesKey(aes_key: &[u8; 32], public_key_pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)?;

    let mut rng = OsRng;
    
    let encrypted_key = public_key.encrypt(
        &mut rng,
        Pkcs1v15Encrypt,
        aes_key,
    )?;

    Ok(encrypted_key)

}

fn DecryptAesKey(encrypted_key: &[u8], private_key_pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)?;

    let decrypted_data = private_key.decrypt(
        Pkcs1v15Encrypt,
        encrypted_key,
    )?;
 
    if decrypted_data.len() != 32 {
        return Err("Decrypted data length mismatch".into());

    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted_data);

    Ok(key.to_vec())
}

fn SaveEncryptedKey(encrypted_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(AES_ENCRPTED_KEY_PATH)?;
    file.write_all(encrypted_key)?;
    Ok(())
}

fn LoadEncryptedKey() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(AES_ENCRPTED_KEY_PATH)?;
    let mut encrypted_key = Vec::new();
    file.read_exact(&mut encrypted_key)?;
    Ok(encrypted_key)
}