use std::sync::Arc;

use crate::{
    app::{self, App},
    db::Database,
    models::{StoredSecret, StoredSecretObject},
};

pub struct KeyValueEngine {}

impl KeyValueEngine {
    pub async fn init() -> std::result::Result<Self, String> {
        return Ok(Self {});
    }
    pub async fn get_secret(&self, app: &App, key: &str) -> Result<StoredSecret, String> {
        let val =
            sqlx::query_as::<_, StoredSecret>("SELECT * FROM tokaysec.kv_store WHERE key = ($1)")
                .bind(&key)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();
        return Ok(val);
    }
    pub async fn store_secret(
        &self,
        app: &App,
        key: &str,
        id: &str,
        secret: StoredSecretObject,
    ) -> Result<String, String> {
        return Ok(sqlx::query_as::<_, (String,)>(
            "INSERT INTO tokaysec.kv_store(id,key,secret) VALUES($1,$2,$3) RETURNING id",
        )
        .bind(&id)
        .bind(&key)
        .bind(serde_json::to_value(&secret).unwrap())
        .fetch_one(&app.database.inner)
        .await
        .unwrap()
        .0);
    }
}
