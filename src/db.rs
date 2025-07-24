use std::{path::Path, sync::Arc};

use chrono::Utc;
use redis::{Client, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow, Pool, Postgres,
    migrate::{self, Migrator},
};

use crate::{app::App, models::Person};

pub struct Database {
    pub inner: Pool<Postgres>,
    pub redis: ConnectionManager,
}

impl Database {
    pub async fn init(dsn: &str, migrations: &str) -> std::result::Result<Self, String> {
        let current_env = std::env::var("CURRENT_ENV").unwrap_or("dev".to_string());
        let pool = Pool::connect(dsn).await.unwrap();
        let migrator = Migrator::new(Path::new(migrations)).await.unwrap();
        migrator.run(&pool).await.unwrap();
        return Ok(Self {
            inner: pool,
            redis: ConnectionManager::new(
                Client::open("redis://127.0.0.1:6379".to_string()).unwrap(),
            )
            .await
            .unwrap(),
        });
    }
}
