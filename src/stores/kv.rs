use std::io::empty;

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    app::{App, EasyResource},
    dek::Dek,
    kek_provider::KekProvider,
    models::{KVStoredValue, WrappedDek},
    secure_buf::SecureBuffer,
    stores::{RetrievedSecretData, Store, kv},
};

#[derive(Serialize, Deserialize)]
pub struct KvStoreStoreData {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KvStoreReturn {
    pub dek: KvStoreReturnDek,
    pub gcm_tag: Vec<u8>,
    pub kmac_tag: Vec<u8>,
    pub nonce: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KvStoreReturnDek {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub data: Vec<u8>,
}

pub struct KvStore {}

impl KvStore {
    pub async fn init() -> Self {
        Self {}
    }
    pub async fn store_secret(
        &self,
        app: &App,
        key: &str,
        store_result: &KvStoreReturn,
        project: &str,
        creator: &str,
    ) -> Result<(), String>
    where
        Self: Sized,
    {
        let added_when = Utc::now();
        let id = app.gen_id().await;
        let dek_id = app.gen_id().await;
        let wrapped_dek = sqlx::query_as::<_, WrappedDek>(
            r#"INSERT INTO tokaysec.wrapped_deks(id,wrapped,nonce,tag,added_when,added_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *"#,
        )
        .bind(&dek_id).bind(&store_result.dek.data).bind(store_result.dek.nonce).bind(store_result.dek.tag)
        .bind(added_when).bind(&creator)
        .fetch_one(&app.database.inner)
        .await
        .unwrap();
        let stored_value = sqlx::query_as::<_, KVStoredValue>(
            r#"INSERT INTO tokaysec.kv_store(id,key,value,gcm_tag,kmac_tag,nonce,dek_used,added_when,added_by,last_updated) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$8) RETURNING *"#,
        )
        .bind(&id).bind(&key).bind(&store_result.data).bind(&store_result.gcm_tag).bind(&store_result.kmac_tag)
        .bind(&store_result.nonce).bind(&wrapped_dek.id).bind(added_when).bind(&creator)
        .fetch_one(&app.database.inner)
        .await
        .unwrap();
        app.create_resource_assignment(
            EasyResource(crate::app::ResourceTypes::Project, &project),
            EasyResource(
                crate::app::ResourceTypes::Secret,
                &format!("kv_store:{}", &stored_value.id),
            ),
            creator,
        )
        .await
        .unwrap();
        return Ok(());
    }
}

#[async_trait::async_trait]
impl Store for KvStore {
    async fn get(&self, app: &App, id: &str) -> RetrievedSecretData
    where
        Self: Sized,
    {
        let kv_data =
            sqlx::query_as::<_, KVStoredValue>(r#"SELECT * FROM tokaysec.kv_store WHERE id = $1"#)
                .bind(&id)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();
        return RetrievedSecretData {
            id: kv_data.id,
            name: kv_data.key,
        };
    }
    async fn retrieve(&self, app: &App, id: &str, kek_provider: &dyn KekProvider) -> ()
    where
        Self: Sized,
    {
        let kv_data =
            sqlx::query_as::<_, KVStoredValue>(r#"SELECT * FROM tokaysec.kv_store WHERE id = $1"#)
                .bind(&id)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();
        let dek_data =
            sqlx::query_as::<_, WrappedDek>(r#"SELECT * FROM tokaysec.wrapped_deks WHERE id = $1"#)
                .bind(&kv_data.dek_used)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();

        let unwrapped_dek: Dek = kek_provider
            .unwrap_dek(
                &dek_data.wrapped,
                dek_data.nonce.try_into().unwrap(),
                dek_data.tag.try_into().unwrap(),
                &kv_data.key,
            )
            .await
            .into();
        let raw_data = unwrapped_dek.unwrap_data(
            kv_data.value,
            kv_data.kmac_tag,
            &kv_data.key,
            kv_data.nonce,
            kv_data.gcm_tag,
        );
        println!("{:?}", String::from_utf8(raw_data.expose().to_vec()));
        return ();
    }
    async fn store(
        &self,
        app: &App,
        project: String,
        kek_provider: &dyn KekProvider,
        data: serde_json::Value,
        creator: &str,
    ) -> KvStoreReturn
    where
        Self: Sized,
    {
        let dek = Dek::init();
        let data: KvStoreStoreData = serde_json::from_value(data).unwrap();
        let sec_data = SecureBuffer::from_slice(&data.value).unwrap();
        drop(data.value);
        let encrypted = dek.wrap_data(sec_data, data.name.to_owned());
        let (wrapped_dek, nonce, tag) = kek_provider
            .wrap_dek(dek, &data.name.to_owned())
            .await
            .unwrap();

        let store_return = KvStoreReturn {
            dek: KvStoreReturnDek {
                nonce,
                tag,
                data: wrapped_dek,
            },
            gcm_tag: encrypted.gcm_tag,
            kmac_tag: encrypted.kmac_tag,
            nonce: encrypted.nonce,
            data: encrypted.data,
        };

        self.store_secret(&app, &data.name, &store_return, &project, &creator)
            .await
            .unwrap();
        return store_return;
    }
}
