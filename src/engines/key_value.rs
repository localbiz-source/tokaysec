use crate::db::Database;

pub struct KeyValueEngine {
    database: Database,
}

impl KeyValueEngine {
    pub async fn init(dsn: &str) -> std::result::Result<Self, String> {
        let db = Database::init("").await?;
        return Ok(Self { database: db });
    }
}
