use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct KekConfig {
    pub provider: String
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub kek: KekConfig,
    pub migrations: String,
    pub postgres: String
}