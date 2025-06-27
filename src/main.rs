mod db;
mod dek;
mod flags;
mod kek_provider;
mod secure_buf;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use openssl::{
    provider::Provider,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};

use ring::rand::SecureRandom;
use sha3::{
    Digest, Keccak384, Sha3_384,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::mem;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    kek_provider::{KekProvider, fs::FileSystemKEKProvider},
    secure_buf::SecureBuffer,
};
use tiny_keccak::{Hasher, Kmac};

#[tokio::main]
async fn main() {
    // Enable OpenSSL fips mode. We want to use FIPS approved modules
    // only and in specific AES-256-GCM amongst others.
    unsafe {
        std::env::set_var(
            "OPENSSL_MODULES",
            "/Users/justin/openssl-fips/lib/ossl-modules",
        )
    };
    unsafe { std::env::set_var("OPENSSL_CONF", "/Users/justin/openssl-fips/ssl/openssl.cnf") };
    unsafe {
        std::env::set_var(
            "DYLD_LIBRARY_PATH",
            "/Users/justin/openssl-fips/lib/ossl-modules:$DYLD_LIBRARY_PATH",
        )
    };
    unsafe { std::env::set_var("OPENSSL_DIR", "/Users/justin/openssl-fips") };

    mem::forget(Provider::load(None, "fips").unwrap());
    let kek_provider = FileSystemKEKProvider::init();
    let secret_to_encrypt: String = String::from("this key is supposed to be a secret.");
    // Generate dek
    let mut _dek: SecureBuffer = SecureBuffer::new(32).unwrap();
    let dek_slice = _dek.expose_mut();
    OsRng.fill_bytes(dek_slice);
    // End Generate dek
    // Generate AAD (additional authenticated data)
    let aad = format!(
        "name={}&key_id={}&version={}",
        "new-secret", "1234", "v0.1.0"
    )
    .into_bytes();
    let aad_hash = sha3::Sha3_256::digest(&aad);
    // End AAD generation
    // FIRST DEK splitting
    let dek = _dek.expose();
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
        &secret_to_encrypt.as_bytes(),
        &mut gcm_tag,
    )
    .unwrap();
    // Finish encryption
    // Wrap the DEK in the Kek and prepare to store along side secret
    let (wrapped_key, dek_nonce) = kek_provider
        .wrap_dek(_dek, "super-secret-name")
        .await
        .unwrap();
    let _dek = kek_provider
        .unwrap_dek(&wrapped_key, dek_nonce, "super-secret-name")
        .await;
    //drop(_dek);
    println!(
        "{:?} {:?} {:?} {:?} {:?}",
        ciphertext, nonce, wrapped_key, dek_nonce, aad
    );
    // End encryption section

    // Decrypt∂
    // Split start
    let dek = _dek.expose();
    let mut aes_key = [0u8; 32];
    let mut kmac_key = [0u8; 32];

    let hk = Hkdf::<Sha3_384>::new(None, dek);
    hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
    hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
    // Split end
    // Compute kmac
    let mut mac = Kmac::v256(&kmac_key, &[]);
    for chunk in &[&ciphertext, &aad] {
        mac.update(chunk);
    }

    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();

    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &aes_key,
        Some(&nonce),
        &aad,
        &ciphertext,
        &gcm_tag,
    )
    .unwrap();
    // decipher end
    let value = Zeroizing::new(plaintext);
    println!("{:?}", String::from_utf8(value.to_vec()));
}
