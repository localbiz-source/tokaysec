use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct StoreConfig {
    pub r#type: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "provider")]
pub enum KMSProviders {
    TokayKMS { base: String },
    Fs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OidcProvider {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub display_name: String,
    pub scopes: Vec<String>
}
#[derive(Serialize, Deserialize, Debug,)]
pub struct Config {
    pub kms: KMSProviders,
    //pub stores: HashMap<String, StoreConfig>,
    pub migrations: String,
    pub postgres: String,
    pub allow_kms_colocation: bool,
    pub base_url: String,
    pub oidc: HashMap<String, OidcProvider>,
}

// Deny / Allow list is a list of
// roles/user ids
