use serde::{Serialize, Deserialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct StoredSecretObject {
    pub ciphertext: Vec<u8>,
    pub kmac_tag: Vec<u8>,
    pub gcm_tag: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub nonce: Vec<u8>
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct StoredSecret {
    pub key: String,
    //pub version: String,
    pub id: String,
    pub secret: serde_json::Value,
}