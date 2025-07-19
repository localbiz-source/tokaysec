use std::collections::HashSet;
use std::{net::SocketAddr, sync::Arc};

use aes_gcm::aead::Payload;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    response::IntoResponse,
    routing::{get, post},
};
use axum_client_ip::ClientIpSource;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use rand::{
    Rng,
    seq::{IteratorRandom, SliceRandom},
};
use reqwest::StatusCode;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snowflaked::Generator;
use sqlx::{
    Pool, Sqlite,
    migrate::Migrator,
    prelude::FromRow,
    sqlite::{SqlitePool, SqlitePoolOptions},
};
use tokio::sync::Mutex;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tss_esapi::constants::{
    CapabilityType, PropertyTag, SessionType, StartupType, Tss2ResponseCode,
};
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{AsymmetricAlgorithm, RsaSchemeAlgorithm};
use tss_esapi::structures::{Auth, CapabilityData, PublicParameters, PublicRsaParameters};
use tss_esapi::tcti_ldr::NetworkTPMConfig;
use tss_esapi::tss2_esys::ESYS_TR_RH_OWNER;
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    handles::PersistentTpmHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        CreatePrimaryKeyResult, Data, Digest, HashScheme, Private, Public, PublicBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    utils::PublicKey,
};

static MIGRATOR: Migrator = sqlx::migrate!();

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct StoredKEK {
    pub id: String,
    pub wrapped_kek: Vec<u8>,
    pub persistent_handle: i32,
    pub wrapped_priv_key: Vec<u8>,
    pub wrapped_pub_key: Vec<u8>,
    // pub nonce: Vec<u8>,
    // pub tag: Vec<u8>,
}

#[derive(Clone)]
pub struct App {
    pub(crate) id_gen: Arc<Mutex<Generator>>,
    pub(crate) database: Pool<Sqlite>,
    pub(crate) tpm_ctx: Option<Arc<Mutex<Context>>>,
}

pub async fn initialize_kek(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // let tcti = TctiNameConf::from_environment_variable()
    //     .unwrap_or(TctiNameConf::Device(Default::default()));
    // let mut ctx = Context::new(tcti).unwrap();
    let mut id_gen = app.id_gen.lock().await;
    let id = id_gen.generate::<i64>().to_string();

    if let Some(ctx) = app.tpm_ctx {
        let ctx = ctx.to_owned();
        let mut ctx = ctx.lock().await;

        // let _session = ctx
        //     .start_auth_session(
        //         None,
        //         None,
        //         None,
        //         SessionType::Hmac,
        //         tss_esapi::structures::SymmetricDefinition::Aes {
        //             key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
        //             mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        //         },
        //         HashingAlgorithm::Sha256,
        //     )
        //     .unwrap();

        // TODO: handle this lock a little better. right now
        // i dont care. because hopefully no one is spamming
        // the create project button!

        drop(id_gen);
        // 0x81000000 to 0x81FFFFFF
        let existing_handles = match ctx
            .get_capability(CapabilityType::Handles, 0x81000000, 256)
            .unwrap()
        {
            (CapabilityData::Handles(handles), _) => handles.to_vec(),
            _ => vec![],
        };

        let used: HashSet<u32> = existing_handles.iter().map(|h| (*h).into()).collect();
        println!("{:?}", used);
        let available = (0x81000000..=0x817FFFFF)
            .filter(|h| !used.contains(h))
            .choose(&mut rand::rngs::OsRng);
        if let Some(available) = available {
            ctx.tr_set_auth(Hierarchy::Owner.into(), Auth::default())
                .unwrap();
            let primary = create_primary(&mut ctx);
            let handle: ObjectHandle = primary.key_handle.into();
            println!("Primary key handle: 0x{:08x}", handle.value());
            ctx.tr_set_auth(handle, Auth::default()).unwrap();
            ctx.execute_with_nullauth_session(|ctx| {
                println!("Evicting to persistent handle: 0x{:08x}", available);

                ctx.evict_control(
                    Provision::Owner,
                    handle,
                    tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(
                        PersistentTpmHandle::new(available).unwrap(),
                    ),
                )
            })
            .unwrap();
            let object_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_st_clear(false)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                // We need a key that can decrypt values - we don't need to worry
                // about signatures.
                .with_decrypt(true)
                // Note that we don't set the key as restricted.
                .build()
                .expect("Failed to build object attributes");

            let rsa_params = PublicRsaParametersBuilder::new()
                // The value for scheme may have requirements set by a combination of the
                // sign, decrypt, and restricted flags. For an unrestricted signing and
                // decryption key then scheme must be NULL. For an unrestricted decryption key,
                // NULL, OAEP or RSAES are valid for use.
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_decryption_key(true)
                // We don't require signatures, but some users may.
                // .with_is_signing_key(true)
                .with_restricted(false)
                .build()
                .expect("Failed to build rsa parameters");

            let key_pub = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_rsa_parameters(rsa_params)
                .with_rsa_unique_identifier(PublicKeyRsa::default())
                .build()
                .unwrap();
            let (enc_private, public) = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.create(primary.key_handle, key_pub, None, None, None, None)
                        .map(|key| (key.out_private, key.out_public))
                })
                .unwrap();
            let salt = SaltString::generate(&mut OsRng);
            let private = enc_private.value();
            // Derive KEK with Argon2id
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                Params::new(65536, 3, 4, Some(32)).unwrap(),
            );

            let hash = argon2
                .hash_password(b"justincatmeow".as_ref(), &salt)
                .unwrap();
            let kek_bytes = hash.hash.unwrap();
            let data_to_encrypt = PublicKeyRsa::try_from(kek_bytes.as_bytes()).unwrap();

            let wrapped_kek = ctx
                .execute_with_nullauth_session(|ctx| {
                    let rsa_pub_key = ctx
                        .load_external_public(public.clone(), Hierarchy::Null)
                        .unwrap();

                    let encrypted = ctx.rsa_encrypt(
                        rsa_pub_key,
                        data_to_encrypt.clone(),
                        RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                        Data::default(),
                    );
                    ctx.flush_context(rsa_pub_key.into()).unwrap();
                    encrypted
                })
                .unwrap();
            let _public = public.marshall().unwrap();

            let id = sqlx::query_as::<_, (String,)>(r#"INSERT INTO kek_store(id,wrapped_kek,persistent_handle,wrapped_priv_key,wrapped_pub_key) VALUES($1,$2,$3,$4,$5) RETURNING id"#)
        .bind(&id).bind(wrapped_kek.value()).bind(available).bind(private)
        .bind(_public).fetch_one(&app.database).await.unwrap();

            ctx.flush_context(handle).unwrap();
        }
    }
    return (StatusCode::OK, json!({"id": id}).to_string()).into_response();
}

#[derive(Serialize, Deserialize)]
pub struct WrapDEKRequest {
    pub dek: Vec<u8>,
    pub secret_name: String,
    pub kek: String,
}
#[derive(Serialize, Deserialize)]
pub struct UnwrapDEKRequest {
    pub wrapped_dek: Vec<u8>,
    pub tag: Vec<u8>,
    pub nonce: Vec<u8>,
    pub secret_name: String,
    pub kek: String,
}

pub async fn wrap_dek(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Json(wrap_deq_request): Json<WrapDEKRequest>,
) -> impl IntoResponse {
    let ctx = app.tpm_ctx.unwrap().to_owned();
    let mut ctx = ctx.lock().await;

    let (wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle) = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>, u32)>(
            r#"SELECT wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle FROM kek_store WHERE id = ($1)"#,
        )
        .bind(wrap_deq_request.kek)
        .fetch_one(&app.database)
        .await
        .unwrap();
    println!(
        "pub_key->{:?}\npriv_key->{:?}\nkek->{:?}\nhandle-> 0x{:08x}",
        wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle
    );
    // TODO: we need to decrypt the SELECTED kek.
    // then encrypt the DEK then zeroize and all that the kek, dek memory
    // then return wrapped DEK ciphertext

    let p_handle = PersistentTpmHandle::new(persistent_handle).unwrap();
    let o_handle = ctx
        .tr_from_tpm_public(tss_esapi::handles::TpmHandle::Persistent(p_handle))
        .unwrap();

    let public_key = Public::unmarshall(&wrapped_pub_key).unwrap();
    let private_key = Private::try_from(wrapped_priv_key).unwrap();
    let decrypted_kek = ctx
        .execute_with_nullauth_session(|ctx| {
            let rsa_priv_key = ctx
                .load(o_handle.into(), private_key.clone(), public_key.clone())
                .unwrap();

            let decrypted = ctx.rsa_decrypt(
                rsa_priv_key,
                PublicKeyRsa::try_from(wrapped_kek).unwrap(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                Data::default(),
            );
            decrypted
        })
        .unwrap();
    let mut nonce: [u8; 12] = [0; 12];
    let sr = ring::rand::SystemRandom::new();
    sr.fill(&mut nonce).unwrap();
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &decrypted_kek.to_vec(),
        Some(&nonce),
        &format!("secret:{}", wrap_deq_request.secret_name).as_bytes(),
        &wrap_deq_request.dek,
        &mut tag,
    )
    .unwrap();
    drop(ctx);

    return (
        StatusCode::OK,
        json!({
            "wrapped_dek": ciphertext.to_vec(),
            "nonce":nonce,
            "tag":tag
        })
        .to_string(),
    )
        .into_response();
}

// {"nonce":[139,57,143,186,132,80,251,200,78,147,175,179],"tag":[71,82,144,71,34,106,97,170,245,224,243,52,51,215,240,230],"wrapped_dek":[59,206,59,113,142,190,237,16,74,186,216,248,131],"secret_name":"w","kek":"7350335679722688512"}
pub async fn unwrap_dek(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Json(unwrap_dek_req): Json<UnwrapDEKRequest>,
) -> impl IntoResponse {
    if let Some(ctx) = app.tpm_ctx {
        let ctx = ctx.to_owned();
        let mut ctx = ctx.lock().await;

        let (wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle) = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>, u32)>(
            r#"SELECT wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle FROM kek_store WHERE id = ($1)"#,
        )
        .bind(unwrap_dek_req.kek)
        .fetch_one(&app.database)
        .await
        .unwrap();
        println!(
            "pub_key->{:?}\npriv_key->{:?}\nkek->{:?}\nhandle-> 0x{:08x}",
            wrapped_pub_key, wrapped_priv_key, wrapped_kek, persistent_handle
        );
        // TODO: we need to decrypt the SELECTED kek.
        // then encrypt the DEK then zeroize and all that the kek, dek memory
        // then return wrapped DEK ciphertext

        let p_handle = PersistentTpmHandle::new(persistent_handle).unwrap();
        let o_handle = ctx
            .tr_from_tpm_public(tss_esapi::handles::TpmHandle::Persistent(p_handle))
            .unwrap();

        let public_key = Public::unmarshall(&wrapped_pub_key).unwrap();
        let private_key = Private::try_from(wrapped_priv_key).unwrap();
        let decrypted_kek = ctx
            .execute_with_nullauth_session(|ctx| {
                let rsa_priv_key = ctx
                    .load(o_handle.into(), private_key.clone(), public_key.clone())
                    .unwrap();

                let decrypted = ctx.rsa_decrypt(
                    rsa_priv_key,
                    PublicKeyRsa::try_from(wrapped_kek).unwrap(),
                    RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                    Data::default(),
                );
                decrypted
            })
            .unwrap();
        drop(ctx);
        let dek_bytes = decrypt_aead(
            Cipher::aes_256_gcm(),
            &decrypted_kek.to_vec(),
            Some(&unwrap_dek_req.nonce),
            &format!("secret:{}", &unwrap_dek_req.secret_name).as_bytes(),
            &unwrap_dek_req.wrapped_dek,
            &&unwrap_dek_req.tag,
        )
        .unwrap();

        return (
            StatusCode::OK,
            json!({
                "unwrapped_dek": dek_bytes
            })
            .to_string(),
        )
            .into_response();
    }
    (StatusCode::INTERNAL_SERVER_ERROR).into_response()
}

pub async fn status(ConnectInfo(_client_addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    (StatusCode::OK).into_response()
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true) // restricted for primary RSA key
        .build()
        .expect("Failed to build object attributes");

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true) // Required for decryption
        .with_restricted(true) // Required for KEK key
        .build()
        .unwrap();

    // Use AES-128 CFB for the inner wrapper
    let symmetric = SymmetricDefinitionObject::AES_128_CFB;

    // For a KEK encrypt/decrypt key, we don’t need a specific RSA scheme (use NULL)
    let rsa_scheme = RsaScheme::create(RsaSchemeAlgorithm::Null, None).unwrap();

    let rsa_parameters = PublicRsaParameters::new(
        symmetric,
        rsa_scheme,
        RsaKeyBits::Rsa1024,
        RsaExponent::default(),
    );

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(Default::default())
        .with_rsa_parameters(rsa_parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::default()) // Empty unique for primary templates
        .build()
        .unwrap();

    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let init = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // let tcti = TctiNameConf::from_environment_variable()
    //     .unwrap_or(TctiNameConf::Device(Default::default()));
    let tcti = TctiNameConf::Swtpm(NetworkTPMConfig::default());
    let mut ctx = Arc::new(Mutex::new(Context::new(tcti).unwrap()));
    // {
    //     let mut _ctx = ctx.lock().await;
    //     _ctx.startup(StartupType::Clear).unwrap();
    //     drop(_ctx)
    // }
    // Example: Get TPM properties
    // let caps = ctx.get_tpm_property(tss_esapi::constants::PropertyTag::NvCountersAvail);
    // println!("TPM Properties: {:?}", caps);
    // let primary = create_primary(&mut ctx);
    // // ctx.evict_control(
    // //     Provision::Owner,
    // //     primary.key_handle.into(),
    // //     tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(
    // //         PersistentTpmHandle::new(0x81010001).unwrap(),
    // //     ),
    // // )
    // // .unwrap();

    // // Begin to create our new RSA key.
    // let object_attributes = ObjectAttributesBuilder::new()
    //     .with_fixed_tpm(true)
    //     .with_fixed_parent(true)
    //     .with_st_clear(false)
    //     .with_sensitive_data_origin(true)
    //     .with_user_with_auth(true)
    //     // We need a key that can decrypt values - we don't need to worry
    //     // about signatures.
    //     .with_decrypt(true)
    //     // Note that we don't set the key as restricted.
    //     .build()
    //     .expect("Failed to build object attributes");

    // let rsa_params = PublicRsaParametersBuilder::new()
    //     // The value for scheme may have requirements set by a combination of the
    //     // sign, decrypt, and restricted flags. For an unrestricted signing and
    //     // decryption key then scheme must be NULL. For an unrestricted decryption key,
    //     // NULL, OAEP or RSAES are valid for use.
    //     .with_scheme(RsaScheme::Null)
    //     .with_key_bits(RsaKeyBits::Rsa2048)
    //     .with_exponent(RsaExponent::default())
    //     .with_is_decryption_key(true)
    //     // We don't require signatures, but some users may.
    //     // .with_is_signing_key(true)
    //     .with_restricted(false)
    //     .build()
    //     .expect("Failed to build rsa parameters");

    // let key_pub = PublicBuilder::new()
    //     .with_public_algorithm(PublicAlgorithm::Rsa)
    //     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    //     .with_object_attributes(object_attributes)
    //     .with_rsa_parameters(rsa_params)
    //     .with_rsa_unique_identifier(PublicKeyRsa::default())
    //     .build()
    //     .unwrap();

    // let (enc_private, public) = ctx
    //     .execute_with_nullauth_session(|ctx| {
    //         ctx.create(primary.key_handle, key_pub, None, None, None, None)value
    //             .map(|key| (key.out_private, key.out_public))
    //     })
    //     .unwrap();

    // let data_to_encrypt = PublicKeyRsa::try_from("TPMs are cool.".as_bytes().to_vec())
    //     .expect("Failed to create buffer for data to encrypt.");

    // let encrypted_data = ctx
    //     .execute_with_nullauth_session(|ctx| {
    //         let rsa_pub_key = ctx
    //             .load_external_public(public.clone(), Hierarchy::Null)
    //             .unwrap();

    //         let encrypted = ctx.rsa_encrypt(
    //             rsa_pub_key,
    //             data_to_encrypt.clone(),
    //             RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
    //             Data::default(),
    //         );
    //         ctx.flush_context(rsa_pub_key.into()).unwrap();
    //         encrypted
    //     })
    //     .unwrap();

    // println!("encrypted_data = {:?}", encrypted_data);
    // assert_ne!(encrypted_data, data_to_encrypt);

    // let decrypted_data = ctx
    //     .execute_with_nullauth_session(|ctx| {
    //         let rsa_priv_key = ctx
    //             .load(primary.key_handle, enc_private.clone(), public.clone())
    //             .unwrap();

    //         let decrypted = ctx.rsa_decrypt(
    //             rsa_priv_key,
    //             encrypted_data,
    //             RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
    //             Data::default(),
    //         );
    //         decrypted
    //     })
    //     .unwrap();

    // println!("data_to_encrypt = {:?}", data_to_encrypt);
    // println!("decrypted_data = {:?}", decrypted_data);
    // ctx.flush_context(primary.key_handle.into()).unwrap();

    let db_path = "sqlite://tokaykms.sqlite";
    let pool = SqlitePoolOptions::new().connect(&db_path).await.unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let id_gen = Arc::new(Mutex::new(Generator::new(1)));
    let app = App {
        database: pool,
        tpm_ctx: Some(ctx),
        id_gen,
    };
    // If table doesn't exist (you can skip if you used sqlite3 to make it)
    let router: Router<()> = Router::new()
        .route("/unwrap", post(unwrap_dek))
        .route("/wrap", post(wrap_dek))
        .route("/kek/init", post(initialize_kek))
        .route("/status", get(status))
        .with_state(app)
        .layer(TraceLayer::new_for_http())
        .layer(ClientIpSource::RightmostXForwardedFor.into_extension());

    let addr = SocketAddr::from(([0, 0, 0, 0], 2323));
    info!("Starting on: {addr:?}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
    return Ok(());
}
