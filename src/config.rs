use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct KekConfig {
    pub provider: String,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub kek: KekConfig,
    pub migrations: String,
    pub postgres: String,
}

// Deny / Allow list is a list of
// roles/user ids
