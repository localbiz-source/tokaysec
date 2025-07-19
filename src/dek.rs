use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{OsRng, rand_core::RngCore},
};
use hkdf::Hkdf;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use ring::rand::SecureRandom;
use sha3::{Digest, Sha3_384};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Kmac};

use crate::secure_buf::SecureBuffer;

pub(crate) struct Dek {
    pub __inner: SecureBuffer,
}

pub struct DekWrapDataResult {
    pub data: Vec<u8>,
    pub gcm_tag: Vec<u8>,
    pub kmac_tag: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Dek {
    pub fn init() -> Self {
        let mut __inner: SecureBuffer = SecureBuffer::new(32).unwrap();
        let dek_slice = __inner.expose_mut();
        OsRng.fill_bytes(dek_slice);
        return Self { __inner };
    }
    pub fn unwrap_data(
        &self,
        data: Vec<u8>,
        kmac_tag: Vec<u8>,
        name: &str,
        nonce: Vec<u8>,
        gcm_tag: Vec<u8>,
    ) -> SecureBuffer {
        let aad = format!("name={}", &name).into_bytes();
        let dek = self.__inner.expose();
        let mut aes_key = [0u8; 32];
        let mut kmac_key = [0u8; 32];

        let hk = Hkdf::<Sha3_384>::new(None, dek);
        hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
        hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
        // Split end
        // Compute kmac
        let mut mac = Kmac::v256(&kmac_key, &[]);
        for chunk in &[&data, &aad] {
            mac.update(chunk);
        }
        // KMAC-256 over ciphertext + AAD
        let mut computed_kmac_tag = [0u8; 32];
        mac.finalize(&mut computed_kmac_tag);
        // Compute kmac end
        // Compare start
        if kmac_tag.ct_ne(&computed_kmac_tag).into() {
            panic!("mismatch: {:?} != {:?}", kmac_tag, computed_kmac_tag);
        }
        let plaintext = decrypt_aead(
            Cipher::aes_256_gcm(),
            &aes_key,
            Some(&nonce),
            &aad,
            &data,
            &gcm_tag,
        )
        .unwrap();
        let secure_buffer = SecureBuffer::from_slice(&plaintext).unwrap();
        drop(plaintext);
        return secure_buffer;
    }

    // takes raw data (data: SecureBuffer) and returns the
    // the cihper text (-> Vec<u8>). This consumes self as
    // whenever we finishing wrapping data we drop the inner
    // secure buffer, zeroing out its memory.
    pub fn wrap_data(&self, data: SecureBuffer, name: String) -> DekWrapDataResult {
        let aad = format!("name={}", &name).into_bytes();
        let aad_hash = sha3::Sha3_256::digest(&aad);
        // End AAD generation
        // FIRST DEK splitting
        let dek = self.__inner.expose();
        let mut aes_key = [0u8; 32];
        let mut kmac_key = [0u8; 32];

        let hk = Hkdf::<Sha3_384>::new(None, dek);
        hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
        hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
        // End first split
        // Start encryption
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let mut nonce: [u8; 12] = [0; 12];
        let sr = ring::rand::SystemRandom::new();
        sr.fill(&mut nonce).unwrap();
        let mut gcm_tag = [0u8; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &aes_key,
            Some(&nonce),
            &aad,
            &data.expose(),
            &mut gcm_tag,
        )
        .unwrap();
        let mut mac = Kmac::v256(&kmac_key, &[]);
        for chunk in &[&ciphertext, &aad] {
            mac.update(chunk);
        }
        // KMAC-256 over ciphertext + AAD
        let mut kmac_tag = [0u8; 32];
        mac.finalize(&mut kmac_tag);
        return DekWrapDataResult {
            data: ciphertext,
            nonce: nonce.to_vec(),
            gcm_tag: gcm_tag.to_vec(),
            kmac_tag: kmac_tag.to_vec(),
        };
    }
}

impl Drop for Dek {
    fn drop(&mut self) {}
}
impl From<SecureBuffer> for Dek {
    fn from(value: SecureBuffer) -> Self {
        return Self { __inner: value };
    }
}
