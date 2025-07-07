use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct KekConfig {
    pub provider: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "provider")]
pub enum KMSProviders {
    TokayKMS { host: String, port: u16 },
    Fs
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub kms: KMSProviders,
    pub migrations: String,
    pub postgres: String,
    pub allow_kms_colocation: bool
}

// Deny / Allow list is a list of
// roles/user ids
