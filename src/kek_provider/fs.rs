use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, Params, PasswordHasher};
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
    async fn unwrap_dek(&self, dek: SecureBuffer) -> () {
        /*
                    let cipher = Aes256Gcm::new_from_slice(self.kek.expose())?;

            // Decrypt DEK
            let dek_bytes = cipher.decrypt(Nonce::from_slice(nonce), wrapped_dek)?;
            SecureBuffer::from_slice(&dek_bytes)
         */
        return ();
    }
    async fn wrap_dek<'a>(&self, dek: &'a SecureBuffer) -> Result<(Vec<u8>, [u8; 12]), String> {
        let cipher = Aes256Gcm::new_from_slice(self._kek.expose()).unwrap();
        let mut nonce: [u8; 12] = [0; 12];
        let sr = ring::rand::SystemRandom::new();
        sr.fill(&mut nonce).unwrap();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), dek.expose())
            .unwrap();
        Ok((ciphertext, nonce))
    }
}
