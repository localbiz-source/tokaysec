use crate::db::Database;
use snowflaked::Generator;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct App {
    pub database: Arc<Database>,
    pub id_gen: Arc<Mutex<Generator>>,
}

impl App {
    pub async fn init(database: Arc<Database>) -> Self {
        Self {
            database,
            id_gen: Arc::new(Mutex::new(Generator::new(1))),
        }
    }
    pub async fn gen_id(&self) -> String {
        let mut id_gen = self.id_gen.lock().await;
        return id_gen.generate::<i64>().to_string();
    }
}
