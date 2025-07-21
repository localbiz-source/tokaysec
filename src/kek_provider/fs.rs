use std::io::Write;

use aes_gcm::aead::Payload;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use ring::rand::SecureRandom;
use tracing::info;
use zeroize::Zeroize;

use crate::dek::Dek;
use crate::{kek_provider::KekProvider, secure_buf::SecureBuffer};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};

pub(crate) struct FileSystemKEKProvider {
    _kek: SecureBuffer,
}

impl FileSystemKEKProvider {
    pub fn init() -> Self
    where
        Self: Sized,
    {
        info!("************************************************************************");
        info!("************************************************************************");
        info!("************************************************************************");
        info!(
            "
\x1B[1;31mUSING THE FILE SYSTEM KEK PROVIDER IS HIGHLY INSECURE. 
CONSIDER USING A CLOUD PROVIDER OR THE TOKAY-KMS. THIS
IS MEANT FOR TESTING PURPOSES ONLY.\x1B[0m
"
        );
        info!("************************************************************************");
        info!("************************************************************************");
        info!("************************************************************************");
        info!("Checking if KEK already exists on fs.");
        let kek = if std::fs::exists("./kek/kek.key").unwrap_or(false) {
            info!("Found KEK already on file system. Loading and then removing.");
            let mut file = std::fs::read("./kek/kek.key").unwrap();
            let kek = SecureBuffer::from_slice(&file).unwrap();
            file.zeroize();
            kek
        } else {
            info!("* KEK does not exists, generating now.");

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
            SecureBuffer::from_slice(kek_bytes.as_bytes()).unwrap()
        };
        return Self { _kek: kek };
    }
}

#[async_trait::async_trait]
impl KekProvider for FileSystemKEKProvider {
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
        dek: Dek,
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
            &dek.__inner.expose(),
            &mut tag,
        )
        .unwrap();
        drop(dek);
        Ok((ciphertext, nonce, tag))
    }
}

impl Drop for FileSystemKEKProvider {
    fn drop(&mut self) {
        let mut kek_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open("./kek/kek.key")
            .unwrap();
        let mut kek_buffer = &mut self._kek.expose();
        kek_file.write_all(&mut kek_buffer).unwrap();
        drop(kek_file);
    }
}
