mod app;
mod audit;
mod config;
mod db;
mod dek;
mod kek_provider;
mod models;
mod policies;
mod routes;
mod secure_buf;
mod stores;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use chrono::format;
use hkdf::Hkdf;
use openssl::{
    conf,
    provider::Provider,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};

use ring::rand::SecureRandom;
use serde_json::json;
use sha3::{
    Digest, Keccak384, Sha3_384,
    digest::{ExtendableOutput, Update, XofReader},
};
use sqlx::{Pool, Postgres};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    mem,
    net::SocketAddr,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Kmac};
use tracing::{info, warn};

use zeroize::Zeroizing;

use crate::{
    app::{App, EasyResource, ResourceTypes, ScopeLevel},
    config::{Config, StoreConfig},
    db::Database,
    kek_provider::{KekProvider, fs::FileSystemKEKProvider, tokaykms::TokayKMSKEKProvider},
    models::{Namespace, Permission, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
    policies::{AccessAction, check_allowed},
    routes::generate_routers,
    secure_buf::SecureBuffer,
    stores::{
        Store,
        kv::{self, KvStore},
    },
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Enable OpenSSL fips mode. We want to use FIPS approved modules
    // only and in specific AES-256-GCM amongst others.
    unsafe {
        std::env::set_var(
            "OPENSSL_MODULES",
            "/Users/justin/openssl-fips/lib/ossl-modules", //"/usr/local/lib64/ossl-modules", //"/Users/justin/openssl-fips/lib/ossl-modules", //"/usr/local/lib64/ossl-modules",
        )
    };
    unsafe { std::env::set_var("OPENSSL_CONF", "/Users/justin/openssl-fips/ssl/openssl.cnf") };
    //home/justin/tokaysec/openssl.cnf") }; //"/Users/justin/openssl-fips/ssl/openssl.cnf") }; // "/home/justin/tokaysec/openssl.cnf"
    unsafe {
        std::env::set_var(
            "DYLD_LIBRARY_PATH",
            "/Users/justin/openssl-fips/lib/ossl-modules:$DYLD_LIBRARY_PATH",
        )
    };
    unsafe {
        std::env::set_var(
            "LD_LIBRARY_PATH",
            "/usr/local/lib64/ossl-modules/:$LD_LIBRARY_PATH",
        )
    };

    /*

        export OPENSSL_DIR=/home/justin/openssl-3.1.2
    export OPENSSL_NO_PKG_CONFIG=1
    export OPENSSL_CONF=/home/justin/tokaysec/openssl.cnf
    export LD_LIBRARY_PATH=/usr/local/lib64/ossl-modules/:$LD_LIBRARY_PATH
    export OPENSSL_LIB_DIR=/home/justin/openssl-3.1.2
    export OPENSSL_INCLUDE_DIR=/home/justin/openssl-3.1.2/include

    cargo build

         */

    mem::forget(Provider::load(None, "fips").unwrap());
    let config_file = std::fs::read_to_string("./Config.toml").unwrap();
    let config: Config = toml::from_str(&config_file).unwrap();
    if config.allow_kms_colocation {
        warn!(
            "\x1B[1;31m************************************************************************\x1B[0m"
        );
        warn!(
            "\x1B[1;33m************************************************************************\x1B[0m"
        );
        warn!(
            "\x1B[1;31m************************************************************************\x1B[0m"
        );
        warn!(
            "\n
\x1B[1;31mONLY ALLOW KMS CO-LOCATION IF THEY ARE RUNNING IN A TIGHT SECURE
ENVIRONMENT OR IF YOU ARE TESTING. PREFER TO HOST KMS ON ANOTHER
HOST IF RUNNING TOKAY-KMS. YOU'VE BEEN WARNED!.\x1B[0m
"
        );
        warn!(
            "\x1B[1;31m************************************************************************\x1B[0m"
        );
        warn!(
            "\x1B[1;33m************************************************************************\x1B[0m"
        );
        warn!(
            "\x1B[1;31m************************************************************************\x1B[0m"
        );
    }
    let db = Arc::new(
        Database::init(&config.postgres, &config.migrations)
            .await
            .unwrap(),
    );
    let app = App::init(db, config).await;
    if !app
        .get_config_value::<bool>("intially_initialized")
        .await
        .unwrap_or(false)
    {
        let instance_id = app.gen_id().await;
        app.set_config_value("instance_id", instance_id)
            .await
            .unwrap();
        info!("Initializing the app for the first time...Please hold.");
        let admin_person = app.create_person("admin").await.unwrap();
        info!("Created admin person with ID: {:?}", admin_person.id);
        // Save the id of the admin account. They can change the name
        // do whatever they want as long as we have the account id.
        app.set_config_value("admin_account_id", admin_person.id.to_owned())
            .await
            .unwrap();
        let default_role = app
            .create_role("default", &admin_person.id, app::ScopeLevel::Instance)
            .await
            .unwrap();
        let special_role = app
            .create_role("special", &admin_person.id, app::ScopeLevel::Instance)
            .await
            .unwrap();
        let default_namespace = app
            .create_namespace("default_namespace", &admin_person.id)
            .await
            .unwrap();
        let kek_provider = app.kek_provider.to_owned();
        let default_project: Project = app
            .create_project(
                (*kek_provider).as_ref(),
                "default_projcet",
                &default_namespace.id,
            )
            .await
            .unwrap();
        let top_secret_project = app
            .create_project(
                (*kek_provider).as_ref(),
                "top_secret_project",
                &default_namespace.id,
            )
            .await
            .unwrap();
        app.create_resource_assignment(
            EasyResource(ResourceTypes::Namespace, &default_namespace.id),
            EasyResource(ResourceTypes::Project, &default_project.id),
            &admin_person.id,
        )
        .await
        .unwrap();
        app.create_resource_assignment(
            EasyResource(ResourceTypes::Namespace, &default_namespace.id),
            EasyResource(ResourceTypes::Project, &default_project.id),
            &admin_person.id,
        )
        .await
        .unwrap();
        app.create_policy_rule_target(
            &format!("proj:{}", &top_secret_project.id),
            app::PolicyRuleTargetAction::Allow,
            &format!("role:{}", &special_role.id),
        )
        .await
        .unwrap();
        app.create_policy_rule_target(
            &format!("proj:{}", &default_project.id),
            app::PolicyRuleTargetAction::Allow,
            &format!("role:{}", &special_role.id),
        )
        .await
        .unwrap();
        // adding to a namespace should be more of a short cut to add to all projects (UI)
        app.create_policy_rule_target(
            &format!("proj:{}", &default_project.id),
            app::PolicyRuleTargetAction::Allow,
            &format!("role:{}", &default_role.id),
        )
        .await
        .unwrap();
        app.create_resource_assignment(
            EasyResource(ResourceTypes::Person, &admin_person.id),
            EasyResource(ResourceTypes::Role, &default_role.id),
            &admin_person.id,
        )
        .await
        .unwrap();

        // these permissions are "hard coded" in actions however but later on
        // I think i am going to make a custom permissions bs...ENTERPRISE EDITION!! jk
        // secret related
        // let perm_groups = ["secrets", "config", "pki"];
        let target = format!("role:{}", &default_role.id);
        app.create_policy_rule_target(
            &target,
            app::PolicyRuleTargetAction::Allow,
            &format!("perm:{}", AccessAction::CreateSecret.to_string()),
        )
        .await
        .unwrap();
        app.create_policy_rule_target(
            &target,
            app::PolicyRuleTargetAction::Allow,
            &format!("perm:{}", AccessAction::UpdateSecret.to_string()),
        )
        .await
        .unwrap();
        app.create_policy_rule_target(
            &target,
            app::PolicyRuleTargetAction::Allow,
            &format!("perm:{}", AccessAction::DeleteSecret.to_string()),
        )
        .await
        .unwrap();
        // Now that everything has intialized we will set this true.
        app.set_config_value("intially_initialized", true)
            .await
            .unwrap();
        app.set_config_value("instance_locked_until_default_is_changed", true)
            .await
            .unwrap();
        info!("Initial initialization is complete!");
    }

    let routes = generate_routers(app).await;
    let addr = SocketAddr::from(([0, 0, 0, 0], 2323));
    info!("Starting on: {addr:?}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
