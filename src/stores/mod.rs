#[async_trait::async_trait]
pub trait Store: Sync {
    async fn init() -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

/*

POST /stores/

*/