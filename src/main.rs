mod app;
mod config;
mod db;
mod dek;
mod engines;
mod flags;
mod kek_provider;
mod models;
mod secure_buf;
mod templated_config;

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
use sqlx::{Pool, Postgres};
use std::{mem, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    app::App,
    config::Config,
    db::Database,
    engines::key_value::KeyValueEngine,
    kek_provider::{KekProvider, fs::FileSystemKEKProvider},
    models::{StoredSecret, StoredSecretObject},
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
            "/usr/local/lib64/ossl-modules", //"/Users/justin/openssl-fips/lib/ossl-modules",
        )
    };
    unsafe { std::env::set_var("OPENSSL_CONF", "/home/justin/tokaysec/openssl.cnf") }; //"/Users/justin/openssl-fips/ssl/openssl.cnf") };
    // unsafe {
    //     std::env::set_var(12
    //         "DYLD_LIBRARY_PATH",
    //         "/Users/justin/openssl-fips/lib/ossl-modules:$DYLD_LIBRARY_PATH",
    //     )
    // };
    unsafe {
        std::env::set_var(
            "LD_LIBRARY_PATH",
            "/usr/local/lib64/ossl-modules/:$LD_LIBRARY_PATH",
        )
    };

    /*

        export OPENSSL_DIR=/home/justin/openssl-3.1.2
    export OPENSSL_NO_PKG_CONFIG=1
    export OPENSSL_CONF=/home/justin/tokaysec/openssl.cnf
    export LD_LIBRARY_PATH=/usr/local/lib64/ossl-modules/:$LD_LIBRARY_PATH
    export OPENSSL_LIB_DIR=/home/justin/openssl-3.1.2
    export OPENSSL_INCLUDE_DIR=/home/justin/openssl-3.1.2/include

    cargo build

         */
    mem::forget(Provider::load(None, "fips").unwrap());
    let config_file = std::fs::read_to_string("./Config.toml").unwrap();
    let config: Config = toml::from_str(&config_file).unwrap();
    let db = Arc::new(
        Database::init(&config.postgres, &config.migrations)
            .await
            .unwrap(),
    );
    let kek_provider = match config.kek.provider.as_str() {
        "fs" => FileSystemKEKProvider::init(),
        unknown @ _ => panic!("Unknown KEK provider set in config file: {:?}", unknown),
    };
    let key_value_engine = KeyValueEngine::init().await.unwrap();
    let app = App::init(db).await;
    println!(
        "{:?}",
        key_value_engine
            .get_secret(&app, "new-secret")
            .await
            .unwrap().id
    );
    // let secret_to_encrypt: String = String::from("this key is supposed to be a secret.");
    // // Generate deks
    // let mut _dek: SecureBuffer = SecureBuffer::new(32).unwrap();
    // let dek_slice = _dek.expose_mut();
    // OsRng.fill_bytes(dek_slice);
    // // End Generate dek
    // // Generate AAD (additional authenticated data)
    // let id = app.gen_id().await;
    // let name = String::from("new-secret");
    // let aad = format!("name={}&key_id={}&version={}", &name, &id, "v0.1.0").into_bytes();
    // let aad_hash = sha3::Sha3_256::digest(&aad);
    // // End AAD generation
    // // FIRST DEK splitting
    // let dek = _dek.expose();
    // let mut aes_key = [0u8; 32];
    // let mut kmac_key = [0u8; 32];

    // let hk = Hkdf::<Sha3_384>::new(None, dek);
    // hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
    // hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
    // // End first split
    // // Start encryption
    // let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    // let mut nonce: [u8; 12] = [0; 12];
    // let sr = ring::rand::SystemRandom::new();
    // sr.fill(&mut nonce).unwrap();
    // let mut gcm_tag = [0u8; 16];
    // let ciphertext = encrypt_aead(
    //     Cipher::aes_256_gcm(),
    //     &aes_key,
    //     Some(&nonce),
    //     &aad,
    //     &secret_to_encrypt.as_bytes(),
    //     &mut gcm_tag,
    // )
    // .unwrap();
    // let mut mac = Kmac::v256(&kmac_key, &[]);
    // for chunk in &[&ciphertext, &aad] {
    //     mac.update(chunk);
    // }
    // // KMAC-256 over ciphertext + AAD
    // let mut kmac_tag = [0u8; 32];
    // mac.finalize(&mut kmac_tag);
    // // Finish encryption
    // // Wrap the DEK in the Kek and prepare to store along side secret
    // let (wrapped_key, dek_nonce, tag) = kek_provider
    //     .wrap_dek(_dek, "super-secret-name")
    //     .await
    //     .unwrap();
    // // let _dek = kek_provider
    // //     .unwrap_dek(&wrapped_key, dek_nonce, tag, "super-secret-name")
    // //     .await;
    // //drop(_dek);
    // let secret = StoredSecret {
    //     name,
    //     version: String::from("v0.1.0"),
    //     id,
    //     secret_object: StoredSecretObject {
    //         ciphertext,
    //         kmac_tag: kmac_tag.to_vec(),
    //         gcm_tag: gcm_tag.to_vec(),
    //         wrapped_dek: wrapped_key,
    //         nonce: nonce.to_vec(),
    //     },
    // };

    // let seet = key_value_engine
    //     .store_secret(&app, "new-secret", secret)
    //     .await
    //     .unwrap();
    // println!(
    //     "{:?} {:?} {:?} {:?} {:?}",
    //     ciphertext, nonce, wrapped_key, dek_nonce, aad
    // );
    // End encryption section

    // Decrypt∂
    // Split start
    // let dek = _dek.expose();
    // let mut aes_key = [0u8; 32];
    // let mut kmac_key = [0u8; 32];

    // let hk = Hkdf::<Sha3_384>::new(None, dek);
    // hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
    // hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
    // // Split end
    // // Compute kmac
    // let mut mac = Kmac::v256(&kmac_key, &[]);
    // for chunk in &[&ciphertext, &aad] {
    //     mac.update(chunk);
    // }
    // // KMAC-256 over ciphertext + AAD
    // let mut computed_kmac_tag = [0u8; 32];
    // mac.finalize(&mut computed_kmac_tag);
    // // Compute kmac end
    // // Compare start
    // if kmac_tag.ct_ne(&computed_kmac_tag).into() {
    //     panic!("mismatch: {:?} != {:?}", kmac_tag, computed_kmac_tag);
    // }

    // let plaintext = decrypt_aead(
    //     Cipher::aes_256_gcm(),
    //     &aes_key,
    //     Some(&nonce),
    //     &aad,
    //     &ciphertext,
    //     &gcm_tag,
    // )
    // .unwrap();
    // // decipher end
    // let value = Zeroizing::new(plaintext);
    // println!("{:?}", String::from_utf8(value.to_vec()));
}
