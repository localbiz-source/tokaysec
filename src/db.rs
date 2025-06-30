use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Pool, Postgres};

pub struct Database {
    pub inner: Pool<Postgres>,
}

impl Database {
    pub async fn init(dsn: &str) -> std::result::Result<Self, String> {
        let current_env = std::env::var("CURRENT_ENV").unwrap_or("dev".to_string());
        return Ok(Self {
            inner: Pool::connect(dsn).await.unwrap(),
        });
    }
}
