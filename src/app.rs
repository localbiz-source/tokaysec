use crate::{
    config::{self, Config},
    db::Database,
    kek_provider::{KekProvider, fs::FileSystemKEKProvider, tokaykms::TokayKMSKEKProvider},
    models::{Namespace, Permission, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
    policies::split,
    stores::{Store, kv::KvStore},
};
use chrono::Utc;
use openidconnect::{
    core::{CoreAuthPrompt, CoreGenderClaim, CoreJwsSigningAlgorithm}, AdditionalProviderMetadata, AuthenticationFlow, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, JsonWebKeySet, Nonce, OAuth2TokenResponse, ProviderMetadata, RedirectUrl, RevocationErrorResponseType, RevocationUrl, Scope, StandardErrorResponse, StandardTokenIntrospectionResponse, StandardTokenResponse
};
use openidconnect::{
    PkceCodeChallenge,
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
        CoreErrorResponseType, CoreGrantType, CoreIdTokenClaims, CoreIdTokenVerifier,
        CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
        CoreProviderMetadata, CoreResponseMode, CoreRevocableToken, CoreSubjectIdentifierType,
        CoreTokenType,
    },
};
use openidconnect::{core::CoreAuthenticationFlow, reqwest};
use serde::{Serialize, de::DeserializeOwned};
use snowflaked::Generator;
use sqlx::{FromRow, Postgres, Type, postgres::PgRow};
use std::{collections::HashMap, hash::Hash, sync::Arc};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct AppOIDCProviderData {
    pub client: Client<
        EmptyAdditionalClaims,
        CoreAuthDisplay,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJsonWebKey,
        CoreAuthPrompt,
        StandardErrorResponse<CoreErrorResponseType>,
        StandardTokenResponse<
            IdTokenFields<
                EmptyAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            >,
            CoreTokenType,
        >,
        StandardTokenIntrospectionResponse<EmptyExtraTokenFields, CoreTokenType>,
        CoreRevocableToken,
        StandardErrorResponse<RevocationErrorResponseType>,
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    pub scopes: Vec<String>,
    pub http: reqwest::Client
}

#[derive(Clone)]
pub struct App {
    pub database: Arc<Database>,
    pub id_gen: Arc<Mutex<Generator>>,
    pub stores: Arc<RwLock<HashMap<String, Box<dyn Store>>>>,
    pub kek_provider: Arc<Box<dyn KekProvider>>,
    pub oidc: Arc<RwLock<HashMap<String, AppOIDCProviderData>>>,
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
    Secret,
}

#[derive(Debug)]
pub struct EasyResource<'a>(pub ResourceTypes, pub &'a str);

impl ToString for ResourceTypes {
    fn to_string(&self) -> String {
        String::from(match self {
            ResourceTypes::Instance => "inst",
            ResourceTypes::Namespace => "nmsp",
            ResourceTypes::Project => "proj",
            ResourceTypes::Person => "prsn",
            ResourceTypes::Permission => "perm",
            ResourceTypes::Role => "role",
            ResourceTypes::Secret => "scrt",
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
            "scrt" => Self::Secret,
            _ => return Err(String::from("Not found.")),
        });
    }
}

impl App {
    pub async fn init(database: Arc<Database>, config: Config) -> Self {
        let mut stores: HashMap<String, Box<dyn Store>> = HashMap::new();
        let mut oidc_providers: HashMap<String, AppOIDCProviderData> = HashMap::new();
        let mut configured_providers = config.oidc.iter();
        while let Some((name, oidc_provider)) = configured_providers.next() {
            let id = ClientId::new(oidc_provider.client_id.to_owned());
            let secret = ClientSecret::new(oidc_provider.client_secret.to_owned());
            let issuer = IssuerUrl::new(oidc_provider.issuer_url.to_owned()).unwrap();
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let provider = CoreProviderMetadata::discover_async(issuer, &http)
                .await
                .unwrap();
            let client = CoreClient::from_provider_metadata(provider, id, Some(secret))
                // Set the URL the user will be redirected to after the authorization process.
                .set_redirect_uri(
                    RedirectUrl::new(format!("{}/api/v1/auth/finish/oidc/{}", &config.base_url, &name))
                        .unwrap(),
                );
            oidc_providers.insert(
                name.to_owned(),
                AppOIDCProviderData {
                    client: client,
                    http,
                    scopes: oidc_provider.scopes.to_owned(),
                },
            );
        }
        let kv_store = KvStore::init().await;
        stores.insert("kv_store".to_string(), Box::new(kv_store));
        let kek_provider: Arc<Box<dyn KekProvider>> = Arc::new(match config.kms {
            config::KMSProviders::Fs => Box::new(FileSystemKEKProvider::init()),
            config::KMSProviders::TokayKMS { base } => Box::new(TokayKMSKEKProvider::init(base)),
        });
        Self {
            database,
            stores: Arc::new(RwLock::new(stores)),
            id_gen: Arc::new(Mutex::new(Generator::new(1))),
            kek_provider,
            oidc: Arc::new(RwLock::new(oidc_providers)),
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
    pub async fn get_project(&self, project_id: &str) -> std::result::Result<Project, String> {
        return Ok(sqlx::query_as::<_, Project>(
            r#"SELECT * FROM tokaysec.projects WHERE id = ($1)"#,
        )
        .bind(project_id)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_project(
        &self,
        kek_provider: &dyn KekProvider,
        name: &str,
        namespace: &str,
    ) -> std::result::Result<Project, String> {
        let new_kek_id = kek_provider.init_new_kek().await.unwrap();

        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Project>(
            r#"INSERT INTO tokaysec.projects(id,name,namespace,kek_id,added_when) VALUES($1,$2,$3,$4,$5) RETURNING *"#,
        )
        .bind(gen_id)
        .bind(&name)
        .bind(&namespace)
        .bind(&new_kek_id)
        .bind(created_when)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_namespace(
        &self,
        name: &str,
        creator_id: &str,
    ) -> std::result::Result<Namespace, String> {
        let created_when = Utc::now();
        let gen_id = self.gen_id().await;
        return Ok(sqlx::query_as::<_, Namespace>(
            r#"INSERT INTO tokaysec.namespaces(id,name,added_when,last_updated,created_by) VALUES($1,$2,$3,$3,$4) RETURNING *"#,
        )
        .bind(gen_id)
        .bind(&name)
        .bind(created_when)
        .bind(&creator_id)
        .fetch_one(&self.database.inner)
        .await
        .unwrap());
    }
    pub async fn create_resource_assignment(
        &self,
        target: EasyResource<'_>,
        resource: EasyResource<'_>,
        assigned_by: &str,
    ) -> std::result::Result<ResourceAssignment, String> {
        let assigned_when = Utc::now();
        return Ok(sqlx::query_as::<_, ResourceAssignment>(
            r#"INSERT INTO tokaysec.resource_assignment(assigned_to,assigned_to_type,resource,resource_type,assigned_by,assigned_when) VALUES($1,$2,$3,$4,$5,$6) RETURNING *"#,
        )
        .bind(&target.1)
        .bind(target.0.to_string())
        .bind(&resource.1)
        .bind(resource.0.to_string())
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
        let (target, target_type) = split(target.to_string());
        let (resource, resource_type) = split(resource.to_string());
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
