use std::path::Path;

use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow, Pool, Postgres,
    migrate::{self, Migrator},
};

pub struct Database {
    pub inner: Pool<Postgres>,
}

impl Database {
    pub async fn init(dsn: &str, migrations: &str) -> std::result::Result<Self, String> {
        let current_env = std::env::var("CURRENT_ENV").unwrap_or("dev".to_string());
        let pool = Pool::connect(dsn).await.unwrap();
        let migrator = Migrator::new(Path::new(migrations)).await.unwrap();
        migrator.run(&pool).await.unwrap();
        return Ok(Self { inner: pool });
    }
}
