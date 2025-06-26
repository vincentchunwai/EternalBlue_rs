use rand::Rng;
use aes::Aes256;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, RsaPrivateKey};
use rsa::pkcs1::{Pkcs1v15Encrypt};
use std::fs::File;
use std::io::{Write, Read}


pub const AES_ENCRPTED_KEY_PATH: &str = "encrypted_key.bin";

fn GenerateAesKey() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut key: [u8; 32] = [0; 32];

    rand::thread_rng().fill(&mut key);
    Ok(key)
}

fn EncryptAesKey(aes_key: &[u8; 32], public_key: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {

    let public_key = RsaPublicKey::from_public_key_pem(public_key)?;

    let mut rng = rand::thread_rng();
    
    let encrypted_key = public_key.encrypt(
        &mut rng,
        Pkcs1v15Encrypt,
        aes_key,
    )?;

    Ok(encrypted_key);

}

fn DecryptAesKey(encrypted_key: &[u8; 32], private_key: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {

    let private_key = RsaPublicKey::from_private_key_pem(private_key)?;

    let decrypted_key = private_key.decrypt(
        Pkcs1v15Encrypt,
        encrypted_key,
    );
 
    Ok(decrypted_key)

}

fn SaveEncryptedKey(encrypted_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(AES_ENCRPTED_KEY_PATH)?;
    file.write_all(encrypted_key)?;
    Ok(())
}

fn LoadEncryptedKey() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut file = File::open(AES_ENCRPTED_KEY_PATH)?;
    let mut encrypted_key = [0u8; 32];
    file.read_exact(&mut encrypted_key)?;
    Ok(encrypted_key)
}