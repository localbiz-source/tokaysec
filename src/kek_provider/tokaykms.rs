use std::io::Write;

use aes_gcm::aead::Payload;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use reqwest::Client;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;
use zeroize::Zeroize;

use crate::dek::Dek;
use crate::{kek_provider::KekProvider, secure_buf::SecureBuffer};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};

pub(crate) struct TokayKMSKEKProvider {
    _http: Client,
}

#[async_trait::async_trait]
impl KekProvider for TokayKMSKEKProvider {
    fn init() -> Self
    where
        Self: Sized,
    {
        Self {
            _http: Client::new(),
        }
    }
    async fn init_new_kek(&self) -> Result<String, String> {
        #[derive(Serialize, Deserialize, Debug)]
        struct InitKekResponse {
            id: String,
        }
        let req: reqwest::Request = self
            ._http
            .post(format!("http://salacious:2323/kek/init"))
            .build()
            .unwrap();

        let res: reqwest::Response = self._http.execute(req).await.unwrap();
        let unwrapped_dek_response: InitKekResponse = res.json().await.unwrap();
        return Ok(unwrapped_dek_response.id);
    }
    async fn unwrap_dek<'a>(
        &self,
        dek: &'a [u8],
        nonce: [u8; 12],
        tag: [u8; 16],
        secret_name: &'a str,
    ) -> SecureBuffer {
        #[derive(Serialize, Deserialize, Debug)]
        struct UnwrapDekResponse {
            unwrapped_dek: Vec<u8>,
        }
        let req: reqwest::Request = self
            ._http
            .post(format!("http://salacious:2323/unwrap"))
            .body(
                json!({
                    "wrapped_dek": dek,
                    "kek": "7352140924433993728",
                    "secret_name": secret_name,
                    "tag": tag,
                    "nonce": nonce
                })
                .to_string(),
            )
            .header("Content-Type", "application/json")
            .build()
            .unwrap();

        let res: reqwest::Response = self._http.execute(req).await.unwrap();
        let unwrapped_dek_response: UnwrapDekResponse = res.json().await.unwrap();
        let buf = SecureBuffer::from_slice(&unwrapped_dek_response.unwrapped_dek).unwrap();
        drop(unwrapped_dek_response);
        return buf;
    }
    async fn wrap_dek<'a>(
        &self,
        dek: Dek,
        secret_name: &'a str,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), String> {
        #[derive(Serialize, Deserialize, Debug)]
        struct WrapDekResponse {
            wrapped_dek: Vec<u8>,
            nonce: [u8; 12],
            tag: [u8; 16],
        }

        let req: reqwest::Request = self
            ._http
            .post(format!("http://salacious:2323/wrap"))
            .body(
                json!({
                    "dek": dek.__inner.expose(),
                    "kek": "7352140924433993728",
                    "secret_name": secret_name
                })
                .to_string(),
            )
            .header("Content-Type", "application/json")
            .build()
            .unwrap();

        let res: reqwest::Response = self._http.execute(req).await.unwrap();
        let wrapped_dek_response: WrapDekResponse = res.json().await.unwrap();
        Ok((
            wrapped_dek_response.wrapped_dek,
            wrapped_dek_response.nonce,
            wrapped_dek_response.tag,
        ))
    }
}
