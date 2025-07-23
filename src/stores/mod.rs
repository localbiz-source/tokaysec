use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{app::App, kek_provider::KekProvider, stores::kv::KvStoreReturn};

pub mod kv;

#[derive(Serialize, Deserialize)]
pub struct RetrievedSecretData {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
// Choosing a secret store is always required.
pub struct StoreUiRequirements {
    pub name: bool,
    pub description: bool,
    pub secret_type: bool,
}


#[async_trait::async_trait]
pub trait Store: Send + Sync {
    fn ui_reqs(&self) -> StoreUiRequirements;
    async fn store(
        &self,
        app: &App,
        project: String,
        kek_provider: &dyn KekProvider,
        data: serde_json::Value,
        creator: &str,
    ) -> KvStoreReturn;
    async fn retrieve(&self, app: &App, data: HashMap<String, String>, kek_provider: &dyn KekProvider) -> ();
    async fn get(&self, app: &App, id: &str) -> RetrievedSecretData;
}

/*

* invokes the store function of {store_name}
POST /stores/{store_name}

* invokes the get function of {store_name}. Passes
the query arguments along to the get functions
GET /stores/{store_name}?{key=value}
*/
