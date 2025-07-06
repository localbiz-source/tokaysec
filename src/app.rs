use crate::{
    db::Database,
    models::{Namespace, Permission, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
};
use chrono::Utc;
use serde::{Serialize, de::DeserializeOwned};
use snowflaked::Generator;
use sqlx::{FromRow, Postgres, Type, postgres::PgRow};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct App {
    pub database: Arc<Database>,
    pub id_gen: Arc<Mutex<Generator>>,
}

pub enum ScopeLevel {
    Instance,
    Namespace,
    Project,
}

impl ToString for ScopeLevel {
    fn to_string(&self) -> String {
        String::from(match self {
            ScopeLevel::Instance => "instance",
            ScopeLevel::Namespace => "namespace",
            ScopeLevel::Project => "project",
        })
    }
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
    pub async fn get_person_by_name(&self, name: &str) -> std::result::Result<Person, String> {
        return Ok(sqlx::query_as::<_, Person>(
            r#"SELECT * FROM tokaysec.people FROM name = ($1)"#,
        )
        .bind(&name)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_person(&self, name: &str) -> std::result::Result<Person, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Person>(r#"INSERT INTO tokaysec.people(id,name,last_updated,created_when) VALUES($1,$2,$3,$3) RETURNING *"#)
            .bind(gen_id).bind(name).bind(created_when).fetch_one(&self.database.inner).await.unwrap());
    }
    pub async fn create_role(
        &self,
        name: &str,
        creator_id: &str,
        scope: ScopeLevel,
    ) -> std::result::Result<Role, String> {
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Role>(r#"INSERT INTO tokaysec.roles(id,name,scope_level,defined_by) VALUES($1,$2,$3,$4) RETURNING *"#)
            .bind(gen_id).bind(&name).bind(&creator_id).bind(scope.to_string()).fetch_one(&self.database.inner).await.unwrap());
    }
    pub async fn create_project(&self, name: &str) -> std::result::Result<Project, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Project>(
            r#"INSERT INTO tokaysec.projects(id,name,added_when) VALUES($1,$2,$3) RETURNING *"#,
        )
        .bind(gen_id)
        .bind(&name)
        .bind(created_when)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_namespace(&self, name: &str) -> std::result::Result<Namespace, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Namespace>(
            r#"INSERT INTO tokaysec.namespaces(id,name,added_when) VALUES($1,$2,$3) RETURNING *"#,
        )
        .bind(gen_id)
        .bind(&name)
        .bind(created_when)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_resource_assignment(
        &self,
        target: &str,
        resource: &str,
        assigned_by: &str,
    ) -> std::result::Result<ResourceAssignment, String> {
        let assigned_when = Utc::now();
        return Ok(sqlx::query_as::<_, ResourceAssignment>(
            r#"INSERT INTO tokaysec.resource_assignment(assigned_to,resource,assigned_by,assigned_when) VALUES($1,$2,$3,$4) RETURNING *"#,
        )
        .bind(&target)
        .bind(&resource)
        .bind(&assigned_by)
        .bind(assigned_when)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_policy_rule_target(
        &self,
        name: &str,
    ) -> std::result::Result<PolicyRuleTarget, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        todo!()
    }
    pub async fn create_permission(&self, name: &str) -> std::result::Result<Permission, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Permission>(r#"INSERT INTO tokaysec.permissions(id,permission,added_when) VALUES($1,$2,$3) RETURNING *"#)
            .bind(gen_id).bind(&name).bind(created_when).fetch_one(&self.database.inner).await.unwrap());
    }
    pub async fn get_config_value<A: DeserializeOwned>(
        &self,
        key: &str,
    ) -> std::result::Result<A, String> {
        let config_value = sqlx::query_as::<_, (serde_json::Value,)>(
            r#"SELECT value FROM tokaysec.config WHERE key = ($1)"#,
        )
        .bind(&key)
        .fetch_one(&self.database.inner)
        .await
        .unwrap();
        return Ok(serde_json::from_value::<A>(config_value.0).unwrap());
    }
    pub async fn set_config_value<A: DeserializeOwned + Serialize>(
        &self,
        key: &str,
        value: A,
    ) -> std::result::Result<A, String> {
        let config_value = sqlx::query_as::<_, (serde_json::Value,)>(
            r#"INSERT INTO tokaysec.config(key,value) VALUES($1,$2::jsonb) ON CONFLICT (key) DO UPDATE SET value = ($2::jsonb) RETURNING value"#,
        )
        .bind(&key)
        .bind(serde_json::to_value(value).unwrap())
        .fetch_one(&self.database.inner)
        .await
        .unwrap();
        return Ok(serde_json::from_value::<A>(config_value.0).unwrap());
    }
}
