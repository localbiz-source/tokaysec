use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use openssl::provider::Provider;

mod dek;
mod kek_provider;
mod secure_buf;
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
    let secret_to_encrypt: String = String::from("super-secret");
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
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret_to_encrypt.as_bytes(),
                aad: &aad,
            },
        )
        .unwrap();
    // Finish encryption
    // Start Kmac 256 tag generation
    //let raw_ciphertext = ciphertext.to_owned();
    let mut mac = Kmac::v256(&kmac_key, &[]);
    for chunk in &[&ciphertext, &aad] {
        mac.update(chunk);
    }
    // KMAC-256 over ciphertext + AAD
    let mut kmac_tag = [0u8; 32];
    mac.finalize(&mut kmac_tag);
    // End Kmac generation
    //ciphertext.extend_from_slice(&kmac_tag);
    // Wrap the DEK in the Kek and prepare to store along side secret
    let (wrapped_key, dek_nonce) = kek_provider.wrap_dek(&_dek).await.unwrap();
    //drop(_dek);
    println!(
        "{:?} {:?} {:?} {:?} {:?} {:?}",
        ciphertext, nonce, kmac_tag, wrapped_key, dek_nonce, aad
    );
    // End encryption section

    // Decrypt
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
    // KMAC-256 over ciphertext + AAD
    let mut computed_kmac_tag = [0u8; 32];
    mac.finalize(&mut computed_kmac_tag);
    // Compute kmac end
    // Compare start
    if kmac_tag.ct_ne(&computed_kmac_tag).into() {
        panic!("mismatch: {:?} != {:?}", kmac_tag, computed_kmac_tag);
    }
    // compare end
    // decipher start
    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .unwrap();
    // decipher end
    let value = Zeroizing::new(plaintext);
    println!("{:?}", String::from_utf8(value.to_vec()));
}
