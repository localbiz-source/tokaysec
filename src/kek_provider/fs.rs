use aes_gcm::aead::Payload;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use ring::rand::SecureRandom;

use crate::{kek_provider::KekProvider, secure_buf::SecureBuffer};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};

pub(crate) struct FileSystemKEKProvider {
    _kek: SecureBuffer,
}

#[async_trait::async_trait]
impl KekProvider for FileSystemKEKProvider {
    fn init() -> Self
    where
        Self: Sized,
    {
        println!("************************************************************************");
        println!("************************************************************************");
        println!("************************************************************************");
        println!(
"
USING THE FILE SYSTEM KEK PROVIDER IS HIGHLY INSECURE. 
CONSIDER USING A CLOUD PROVIDER OR THE TOKAY-KMS. THIS
IS MEANT FOR TESTING PURPOSES ONLY.
");
        println!("************************************************************************");
        println!("************************************************************************");
        println!("************************************************************************");
        let salt = SaltString::generate(&mut OsRng);

        // Derive KEK with Argon2id
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, Some(32)).unwrap(),
        );

        let hash = argon2
            .hash_password(b"justincatmeow".as_ref(), &salt)
            .unwrap();
        let kek_bytes = hash.hash.unwrap();

        // Store KEK in secure buffer
        let kek = SecureBuffer::from_slice(kek_bytes.as_bytes()).unwrap();

        return Self { _kek: kek };
    }
    async fn unwrap_dek<'a>(
        &self,
        dek: &'a [u8],
        nonce: [u8; 12],
        tag: [u8; 16],
        secret_name: &'a str,
    ) -> SecureBuffer {
        let dek_bytes = decrypt_aead(
            Cipher::aes_256_gcm(),
            &self._kek.expose(),
            Some(&nonce),
            &format!("secret:{}", secret_name).as_bytes(),
            &dek,
            &tag,
        )
        .unwrap();
        return SecureBuffer::from_slice(&dek_bytes).unwrap();
    }
    async fn wrap_dek<'a>(
        &self,
        dek: SecureBuffer,
        secret_name: &'a str,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), String> {
        let mut nonce: [u8; 12] = [0; 12];
        let sr = ring::rand::SystemRandom::new();
        sr.fill(&mut nonce).unwrap();
        let mut tag = [0u8; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self._kek.expose(),
            Some(&nonce),
            &format!("secret:{}", secret_name).as_bytes(),
            &dek.expose(),
            &mut tag,
        )
        .unwrap();
        drop(dek);
        Ok((ciphertext, nonce, tag))
    }
}
