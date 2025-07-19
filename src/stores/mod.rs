use crate::{app::App, kek_provider::KekProvider, stores::kv::KvStoreReturn};

pub mod kv;

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn init() -> Self
    where
        Self: Sized;
    async fn store(
        &self,
        app: &App,
        project: String,
        kek_provider: &dyn KekProvider,
        data: serde_json::Value,
        creator: &str,
    ) -> KvStoreReturn;
    async fn get(&self, app: &App, id: &str, kek_provider: &dyn KekProvider) -> ();
}

/*

POST /stores/

*/
