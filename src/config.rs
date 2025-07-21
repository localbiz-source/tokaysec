use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct StoreConfig {
    pub r#type: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct KekConfig {
    pub provider: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "provider")]
pub enum KMSProviders {
    TokayKMS { base: String },
    Fs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub kms: KMSProviders,
    //pub stores: HashMap<String, StoreConfig>,
    pub migrations: String,
    pub postgres: String,
    pub allow_kms_colocation: bool,
}

// Deny / Allow list is a list of
// roles/user ids
