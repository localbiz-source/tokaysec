use serde::{Deserialize, Serialize};

use crate::{app::App, kek_provider::KekProvider, stores::kv::KvStoreReturn};

pub mod kv;

#[derive(Serialize, Deserialize)]
pub struct RetrievedSecretData {
    pub id: String,
    pub name: String,
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn store(
        &self,
        app: &App,
        project: String,
        kek_provider: &dyn KekProvider,
        data: serde_json::Value,
        creator: &str,
    ) -> KvStoreReturn;
    async fn retrieve(&self, app: &App, id: &str, kek_provider: &dyn KekProvider) -> ();
    async fn get(&self, app: &App, id: &str) -> RetrievedSecretData;
}

/*

* invokes the store function of {store_name}
POST /stores/{store_name}

* invokes the get function of {store_name}. Passes
the query arguments along to the get functions
GET /stores/{store_name}?{key=value}
*/
