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
use std::{collections::HashMap, io::Read, mem, sync::Arc};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Kmac};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{
    app::{App, ResourceTypes, ScopeLevel},
    config::{Config, StoreConfig},
    db::Database,
    kek_provider::{fs::FileSystemKEKProvider, tokaykms::TokayKMSKEKProvider, KekProvider},
    models::{Namespace, Permission, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
    policies::{check_allowed, AccessAction},
    secure_buf::SecureBuffer,
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
    let app = Arc::new(App::init(db).await);
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
        let default_namespace = app.create_namespace("default_namespace").await.unwrap();
        let default_project = app
            .create_project("default_projcet", Some(&default_namespace.id))
            .await
            .unwrap();
        let top_secret_project = app
            .create_project("top_secret_project", Some(&default_namespace.id))
            .await
            .unwrap();
        app.create_resource_assignment(
            &format!("nmsp:{}", &default_namespace.id),
            &format!("proj:{}", &default_project.id),
            &admin_person.id,
        )
        .await
        .unwrap();
        app.create_resource_assignment(
            &format!("nmsp:{}", &default_namespace.id),
            &format!("proj:{}", &top_secret_project.id),
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
            &format!("prsn:{}", &admin_person.id),
            &format!("role:{}", &default_role.id),
            &admin_person.id,
        )
        .await
        .unwrap();

        // these permissions are "hard coded" in actions however but later on
        // I think i am going to make a custom permissions bs...ENTERPRISE EDITION!! jk
        // secret related
        let perm_groups = ["secrets", "config", "pki"];
        let target = format!("role:{}", &default_role.id);
        for perm_group in perm_groups {
            let read_p = app
                .create_permission(&format!("read:{perm_group}"), None)
                .await
                .unwrap();
            let write_p = app
                .create_permission(&format!("write:{perm_group}"), None)
                .await
                .unwrap();
            app.create_policy_rule_target(
                &target,
                app::PolicyRuleTargetAction::Allow,
                &format!("perm:{}", &read_p.id),
            )
            .await
            .unwrap();
            app.create_policy_rule_target(
                &target,
                app::PolicyRuleTargetAction::Allow,
                &format!("perm:{}", &write_p.id),
            )
            .await
            .unwrap();
        }
        // some special perms...for special things
        let manage_ca = app
            .create_permission(&format!("manage:ca"), None)
            .await
            .unwrap();
        // this includes revoking shit and alat. The pki above is everything BUT these two
        let manage_crl = app
            .create_permission(&format!("manage:crl"), None)
            .await
            .unwrap();
        app.create_policy_rule_target(
            &target,
            app::PolicyRuleTargetAction::Allow,
            &format!("perm:{}", &manage_ca.id),
        )
        .await
        .unwrap();
        app.create_policy_rule_target(
            &target,
            app::PolicyRuleTargetAction::Allow,
            &format!("perm:{}", &manage_crl.id),
        )
        .await
        .unwrap();
        // pki related
        // Now that everything has intialized we will set this true.
        app.set_config_value("intially_initialized", true)
            .await
            .unwrap();
        info!("Initial initialization is complete!");
    }
    let kek_provider: &dyn KekProvider = match config.kms {
        config::KMSProviders::Fs => &FileSystemKEKProvider::init(),
        config::KMSProviders::TokayKMS { host, port } => &TokayKMSKEKProvider::init(),
    };
    // TODO: clean this up. break it up.
    let mut formated_namespaces = vec![];
    for namespace in sqlx::query_as::<_, Namespace>(r#"SELECT * FROM tokaysec.namespaces"#)
        .fetch_all(&app.database.inner)
        .await
        .unwrap()
    {
        let mut formated_projects = vec![];
        let mut formated_roles = vec![];
        for role in sqlx::query_as::<_, Role>(
            r#"SELECT * FROM tokaysec.roles WHERE scope_level = $1 AND defined_by = ($2)"#,
        )
        .bind(ScopeLevel::Namespace.to_string())
        .bind(&namespace.id)
        .fetch_all(&app.database.inner)
        .await
        .unwrap()
        {
            formated_roles.push(json!({
                "name": role.name
            }));
        }

        for project in sqlx::query_as::<_, Project>(
            r#"SELECT * FROM tokaysec.projects WHERE namespace = ($1)"#,
        )
        .bind(&namespace.id)
        .fetch_all(&app.database.inner)
        .await
        .unwrap()
        {
            let mut fomrated_rules = vec![];
            let target_rules = sqlx::query_as::<_, PolicyRuleTarget>(
                r#"SELECT * FROM tokaysec.policy_rule_target WHERE target = ($1) AND target_type = 'proj'"#,
            )
            .bind(&project.id)
            .fetch_all(&app.database.inner)
            .await
            .unwrap();
            for rule in target_rules {
                fomrated_rules.push(match rule.action {
                    0 => format!("-{}:{}", rule.resource_type, rule.resource),
                    1 => format!("+{}:{}", rule.resource_type, rule.resource),
                    _ => continue,
                })
            }
            formated_projects.push(json!({
                "name": project.name,
                "rules": fomrated_rules
            }));
        }
        formated_namespaces.push(json!({
            "projects": formated_projects,
            "roles": formated_roles,
            "name": namespace.name
        }));
    }
    let mut formated_roles = vec![];
    let mut formated_people = vec![];
    for role in sqlx::query_as::<_, Role>(
        r#"SELECT * FROM tokaysec.roles WHERE scope_level = 'instance' OR scope_level = NULL"#,
    )
    .fetch_all(&app.database.inner)
    .await
    .unwrap()
    {
        let mut formated_perms = vec![];
        let permissions = sqlx::query_as::<_, PolicyRuleTarget>(
            r#"SELECT * FROM tokaysec.policy_rule_target WHERE target = $1 AND target_type = 'role'"#,
        ).bind(role.id)
        .fetch_all(&app.database.inner)
        .await
        .unwrap();
        for perm in permissions {
            formated_perms.push(match perm.action {
                0 => format!("-{}:{}", perm.resource_type, perm.resource),
                1 => format!("+{}:{}", perm.resource_type, perm.resource),
                _ => continue,
            })
        }
        formated_roles.push(json!({
            "name": role.name,
            "permissions": formated_perms
        }))
    }
    for person in sqlx::query_as::<_, Person>(r#"SELECT * FROM tokaysec.people"#)
        .fetch_all(&app.database.inner)
        .await
        .unwrap()
    {
        let mut formated_roles = vec![];
        for assignment in sqlx::query_as::<_, ResourceAssignment>(
            r#"SELECT * FROM tokaysec.resource_assignment WHERE assigned_to = $1"#,
        )
        .bind(person.id)
        .fetch_all(&app.database.inner)
        .await
        .unwrap()
        {
            match ResourceTypes::try_from(assignment.resource_type.as_str()).unwrap() {
                ResourceTypes::Instance => todo!(),
                ResourceTypes::Namespace => todo!(),
                ResourceTypes::Project => todo!(),
                ResourceTypes::Person => todo!(),
                ResourceTypes::Permission => todo!(),
                ResourceTypes::Role => {
                    formated_roles.push(format!(
                        "+{}:{}",
                        assignment.resource_type, assignment.resource
                    ));
                }
            }
        }
        formated_people.push(json!({
            "name": person.name,
            "roles": formated_roles
        }));
    }
    println!(
        "(checks:{:?}) \n\n  {:#?}",
        check_allowed(
            &app,
            Some(String::from("7350660643688550400")),
            Some(String::from("7350660643692744705")),
            String::from("proj:7350660643692744704"),
            String::from("7350660643675967489"),
            AccessAction::Manage
        ).await,
        json!({
            "people": formated_people,
            "roles": formated_roles,
            "namespaces": formated_namespaces
        })
    );
    //app.database.create_person(app.to_owned(), "jharris").await;
    // println!(
    //     "{:?}",
    //     key_value_engine
    //         .get_secret(&app, "new-secret")
    //         .await
    //         .unwrap()
    //         .id
    // );
    // let secret_to_encrypt: String = String::from("this key is supposed to be a secret.");
    // // Generate deks
    // let mut _dek: SecureBuffer = SecureBuffer::new(32).unwrap();
    // let dek_slice = _dek.expose_mut();
    // OsRng.fill_bytes(dek_slice);
    // // End Generate dek
    // // Generate AAD (additional authenticated data)
    // let id = app.gen_id().await;
    // let name = String::from("new-secret");
    // let aad = format!("name={}&key_id={}&version={}", &name, &id, "v0.1.0").into_bytes();
    // let aad_hash = sha3::Sha3_256::digest(&aad);
    // // End AAD generation
    // // FIRST DEK splitting
    // let dek = _dek.expose();
    // let mut aes_key = [0u8; 32];
    // let mut kmac_key = [0u8; 32];

    // let hk = Hkdf::<Sha3_384>::new(None, dek);
    // hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
    // hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
    // // End first split
    // // Start encryption
    // let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    // let mut nonce: [u8; 12] = [0; 12];
    // let sr = ring::rand::SystemRandom::new();
    // sr.fill(&mut nonce).unwrap();
    // let mut gcm_tag = [0u8; 16];
    // let ciphertext = encrypt_aead(
    //     Cipher::aes_256_gcm(),
    //     &aes_key,
    //     Some(&nonce),
    //     &aad,
    //     &secret_to_encrypt.as_bytes(),
    //     &mut gcm_tag,
    // )
    // .unwrap();
    // let mut mac = Kmac::v256(&kmac_key, &[]);
    // for chunk in &[&ciphertext, &aad] {
    //     mac.update(chunk);
    // }
    // // KMAC-256 over ciphertext + AAD
    // let mut kmac_tag = [0u8; 32];
    // mac.finalize(&mut kmac_tag);
    // // Finish encryption
    // // Wrap the DEK in the Kek and prepare to store along side secret
    // let (wrapped_key, dek_nonce, tag) = kek_provider
    //     .wrap_dek(_dek, "super-secret-name")
    //     .await
    //     .unwrap();
    // let _dek = kek_provider
    //     .unwrap_dek(&wrapped_key, dek_nonce, tag, "super-secret-name")
    //     .await;
    // //drop(_dek);

    // // let seet = key_value_engine
    // //     .store_secret(
    // //         &app,
    // //         "new-secret",
    // //         &id,
    // //         StoredSecretObject {
    // //             ciphertext,
    // //             kmac_tag: kmac_tag.to_vec(),
    // //             gcm_tag: gcm_tag.to_vec(),
    // //             wrapped_dek: wrapped_key,
    // //             nonce: nonce.to_vec(),
    // //         },
    // //     )
    // //     .await
    // //     .unwrap();
    // // println!(
    // //     "{:?} {:?} {:?} {:?} {:?}",
    // //     ciphertext, nonce, wrapped_key, dek_nonce, aad
    // // );
    // // End encryption section

    // // Decrypt∂
    // // Split start
    // let dek = _dek.expose();
    // let mut aes_key = [0u8; 32];
    // let mut kmac_key = [0u8; 32];

    // let hk = Hkdf::<Sha3_384>::new(None, dek);
    // hk.expand(b"AES-256-GCM", &mut aes_key).unwrap();
    // hk.expand(b"KMAC-256", &mut kmac_key).unwrap();
    // // Split end
    // // Compute kmac
    // let mut mac = Kmac::v256(&kmac_key, &[]);
    // for chunk in &[&ciphertext, &aad] {
    //     mac.update(chunk);
    // }
    // // KMAC-256 over ciphertext + AAD
    // let mut computed_kmac_tag = [0u8; 32];
    // mac.finalize(&mut computed_kmac_tag);
    // // Compute kmac end
    // // Compare start
    // if kmac_tag.ct_ne(&computed_kmac_tag).into() {
    //     panic!("mismatch: {:?} != {:?}", kmac_tag, computed_kmac_tag);
    // }

    // let plaintext = decrypt_aead(
    //     Cipher::aes_256_gcm(),
    //     &aes_key,
    //     Some(&nonce),
    //     &aad,
    //     &ciphertext,
    //     &gcm_tag,
    // )
    // .unwrap();
    // // decipher end
    // let value = Zeroizing::new(plaintext);
    // println!("{:?}", String::from_utf8(value.to_vec()));
}
