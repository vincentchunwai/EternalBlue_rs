use rsa::{RsaPublicKey, RsaPrivateKey};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rsa::traits::PublicKeyParts;
use rand::Rng;
use rsa::rand_core::OsRng;

const RSA_BITS: usize = 2048;
const RSA_PRIVATE_KEY: &str = "rsa_private_key.pem";

fn GenerateRSAKeyPair() -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn std::error::Error>> {
    
    let private_key = RsaPrivateKey::new(&mut OsRng, RSA_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((private_key, public_key))

}

fn SavePrivateKey(private_key: &RsaPrivateKey) -> Result<(), Box<dyn std::error::Error>> {
 
    let private_key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
    std::fs::write(RSA_PRIVATE_KEY, private_key_pem.as_bytes())?;
    Ok(())
}

fn LoadPrivateKey() -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {

    let private_key_pem = std::fs::read_to_string(RSA_PRIVATE_KEY)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)?;
    Ok(private_key)
}

fn ExtractPublicKey(private_key: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(private_key)
}

// cargo test --lib -- rsa::tests --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_rsa_key_pair() {
        let result = GenerateRSAKeyPair();
        assert!(result.is_ok());

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.size(), RSA_BITS / 8);
        assert_eq!(public_key.size(), RSA_BITS / 8);
    }

    #[test]
    fn test_save_and_load_private_key() {
        let (private_key, _) = GenerateRSAKeyPair().unwrap();

        let save_result = SavePrivateKey(&private_key);
        assert!(save_result.is_ok());

        let file_exists = std::path::Path::new(RSA_PRIVATE_KEY).exists();
        assert!(file_exists, "Private key file should exist after saving");

        let abs_path = std::fs::canonicalize(RSA_PRIVATE_KEY).unwrap();
        println!("Private key saved at: {}", abs_path.display());

        std::thread::sleep(std::time::Duration::from_secs(1)); // Ensure file is written before loading

        match std::fs::read_to_string(RSA_PRIVATE_KEY) {
            Ok(content) => {
                println!("-------- Private Key Content --------");
                println!("{}", content);
                println!("-------------------------------------");
            },
            Err(e) => {
                println!("Failed to read private key file: {}", e);
                assert!(false, "Failed to read private key file");
            }
        }

        let loaded_key_result = LoadPrivateKey();
        assert!(loaded_key_result.is_ok());

        let loaded_key = loaded_key_result.unwrap();

        // compare n and e values to ensure keys are the same
        assert_eq!(private_key.n(), loaded_key.n());
        assert_eq!(private_key.e(), loaded_key.e());


        fs::remove_file(RSA_PRIVATE_KEY).unwrap();


    }

    #[test]
    fn test_extract_public_key() {
        let (private_key, original_public_key) = GenerateRSAKeyPair().unwrap();
        let extracted_public_key = ExtractPublicKey(&private_key);

        assert_eq!(original_public_key.n(), extracted_public_key.n());
        assert_eq!(original_public_key.e(), extracted_public_key.e());
    }
}