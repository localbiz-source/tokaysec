use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct StoredSecretObject {
    pub ciphertext: Vec<u8>,
    pub kmac_tag: Vec<u8>,
    pub gcm_tag: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, FromRow)]

pub struct ResourceAssignment {
    pub resource: String,
    pub assigned_to: String,
    pub assigned_when: DateTime<Utc>,
    pub assigned_by: String,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct StoredSecret {
    pub key: String,
    //pub version: String,
    pub id: String,
    pub secret: serde_json::Value,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct Person {
    pub id: String,
    pub name: String,
    pub flags: i64,
    pub last_updated: DateTime<Utc>,
    pub created_when: DateTime<Utc>,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct Credential {
    pub id: String,
    pub created_by: String,
    pub public_key: Vec<u8>,
    pub count: i64,
    pub last_updated: DateTime<Utc>,
    pub created_when: DateTime<Utc>,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub scope_level: Option<String>,
    pub defined_by: String,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct PolicyRuleTarget {
    pub id: String,
    pub target: String,
    pub action: i32,
    pub resource: String,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct Permission {
    pub id: String,
    pub permission: String,
    pub added_when: DateTime<Utc>,
}
#[derive(Serialize, Deserialize, FromRow)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub added_when: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct Namespace {
    pub id: String,
    pub name: String,
    pub added_when: DateTime<Utc>,
}
/*

Name scoping : relating a named item to a certain stratum

Namespace, Project - Order matters. Insstance level scope is global, no prefix.

<namespace>-<project>-<name of obj>
<project>-<name of obj>

This allows for the same name that makes sense for a position to
be applied in different namespaces or projects and scoped to the
relative poeple and permissions. Exmaple:

Namespaces can be thought of as teams that share the same
instance of TokaySec. So two devteams focusing on different
tasks but both need access to secrets management. These namespaces
are isolated and scoped within so projects, and roles, and permissions,
cannot be shared between them unless specified globally in the instance
level policy.
*/
