use crate::{
    db::Database,
    models::{Namespace, Permission, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
    stores::Store,
};
use chrono::Utc;
use serde::{Serialize, de::DeserializeOwned};
use snowflaked::Generator;
use sqlx::{FromRow, Postgres, Type, postgres::PgRow};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

pub struct App {
    pub database: Arc<Database>,
    pub id_gen: Arc<Mutex<Generator>>,
    pub stores: Arc<RwLock<HashMap<String, Box<dyn Store>>>>,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum PolicyRuleTargetAction {
    Allow,
    Deny,
    FallThrough,
}

impl Into<i32> for PolicyRuleTargetAction {
    fn into(self) -> i32 {
        match self {
            PolicyRuleTargetAction::Allow => 1,
            PolicyRuleTargetAction::Deny => 0,
            PolicyRuleTargetAction::FallThrough => 3,
        }
    }
}

impl From<i32> for PolicyRuleTargetAction {
    fn from(value: i32) -> Self {
        match value {
            1 => PolicyRuleTargetAction::Allow,
            3 => PolicyRuleTargetAction::FallThrough,
            _ => PolicyRuleTargetAction::Deny,
        }
    }
}

impl TryFrom<&str> for PolicyRuleTargetAction {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        return Ok(match value {
            "allow" => Self::Allow,
            "+" => Self::Allow,
            "deny" => Self::Deny,
            "-" => Self::Deny,
            _ => Self::Deny,
        });
    }
}

#[derive(Debug)]
pub enum ResourceTypes {
    Instance,
    Namespace,
    Project,
    Person,
    Permission,
    Role,
}

#[derive(Debug)]
pub struct EasyResource<'a>(ResourceTypes, &'a str);

impl ToString for ResourceTypes {
    fn to_string(&self) -> String {
        String::from(match self {
            ResourceTypes::Instance => "inst",
            ResourceTypes::Namespace => "nmsp",
            ResourceTypes::Project => "proj",
            ResourceTypes::Person => "prsn",
            ResourceTypes::Permission => "perm",
            ResourceTypes::Role => "role",
        })
    }
}

impl TryFrom<&str> for ResourceTypes {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        return Ok(match value {
            "inst" => Self::Instance,
            "nmsp" => Self::Namespace,
            "proj" => Self::Project,
            "prsn" => Self::Person,
            "perm" => Self::Permission,
            "role" => Self::Role,
            _ => return Err(String::from("Not found.")),
        });
    }
}

impl App {
    pub async fn init(database: Arc<Database>) -> Self {
        Self {
            database,
            stores: Arc::new(RwLock::new(HashMap::new())),
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
        return Ok(sqlx::query_as::<_, Role>(r#"INSERT INTO tokaysec.roles(id,name,scope_level,defined_by) VALUES($1,$2,$4,$3) RETURNING *"#)
            .bind(gen_id).bind(&name).bind(&creator_id).bind(scope.to_string()).fetch_one(&self.database.inner).await.unwrap());
    }
    pub async fn create_project(
        &self,
        name: &str,
        namespace: Option<&str>,
    ) -> std::result::Result<Project, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Project>(
            r#"INSERT INTO tokaysec.projects(id,name,namespace,added_when) VALUES($1,$2,$3,$4) RETURNING *"#,
        )
        .bind(gen_id)
        .bind(&name)
        .bind(&namespace)
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
        let split = target.split(":").collect::<Vec<&str>>();
        let (assign_to, assign_to_type) = if let Some(first) = split.get(0)
            && let Some(second) = split.get(1)
        {
            let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
            (*second, r#type)
        } else {
            panic!()
        };
        let split_resource = resource.split(":").collect::<Vec<&str>>();
        let (resource, resource_type) = if let Some(first) = split_resource.get(0)
            && let Some(second) = split_resource.get(1)
        {
            let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
            (*second, r#type)
        } else {
            panic!()
        };
        return Ok(sqlx::query_as::<_, ResourceAssignment>(
            r#"INSERT INTO tokaysec.resource_assignment(assigned_to,assigned_to_type,resource,resource_type,assigned_by,assigned_when) VALUES($1,$2,$3,$4,$5,$6) RETURNING *"#,
        )
        .bind(&assign_to)
        .bind(assign_to_type.to_string())
        .bind(&resource)
        .bind(resource_type.to_string())
        .bind(&assigned_by)
        .bind(assigned_when)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_policy_rule_target(
        &self,
        target: &str,
        action: PolicyRuleTargetAction,
        resource: &str,
    ) -> std::result::Result<PolicyRuleTarget, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        let split = target.split(":").collect::<Vec<&str>>();
        let (target, target_type) = if let Some(first) = split.get(0)
            && let Some(second) = split.get(1)
        {
            let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
            (*second, r#type)
        } else {
            panic!()
        };
        let split_resource = resource.split(":").collect::<Vec<&str>>();
        let (resource, resource_type) = if let Some(first) = split_resource.get(0)
            && let Some(second) = split_resource.get(1)
        {
            let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
            (*second, r#type)
        } else {
            panic!()
        };
        let action: i32 = action.into();
        return Ok(sqlx::query_as::<_, PolicyRuleTarget>(r#"INSERT INTO tokaysec.policy_rule_target(id,target,target_type,action,resource,resource_type) VALUES($1,$2,$3,$4,$5,$6) RETURNING *"#)
            .bind(gen_id).bind(target).bind(target_type.to_string()).bind(action).bind(resource).bind(resource_type.to_string()).fetch_one(&self.database.inner).await.unwrap());
    }
    pub async fn create_permission(
        &self,
        name: &str,
        scope_level: Option<ScopeLevel>,
    ) -> std::result::Result<Permission, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Permission>(r#"INSERT INTO tokaysec.permissions(id,permission,scope_level,added_when) VALUES($1,$2,$3,$4) RETURNING *"#)
            .bind(gen_id).bind(&name).bind(scope_level.map(|e| e.to_string())).bind(created_when).fetch_one(&self.database.inner).await.unwrap());
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
