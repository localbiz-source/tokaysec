use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

#[derive(Serialize, Deserialize, Debug, FromRow)]
pub struct AuditLog {}

#[derive(Serialize, Deserialize)]
pub struct Audit {}
