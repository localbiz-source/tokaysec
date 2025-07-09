use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    response::IntoResponse,
    routing::{get, post},
};
use axum_client_ip::ClientIpSource;
use rand::{
    Rng,
    seq::{IteratorRandom, SliceRandom},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
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
        CreatePrimaryKeyResult, Data, Digest, HashScheme, PublicBuilder, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
};

static MIGRATOR: Migrator = sqlx::migrate!();

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct StoredKEK {
    pub id: String,
    pub wrapped_kek: Vec<u8>,
    pub persistent_handle: i32,
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
    if let Some(ctx) = app.tpm_ctx {
        // TODO: handle this lock a little better. right now
        // i dont care. because hopefully no one is spamming
        // the create project button!
        let ctx = ctx.to_owned();
        let mut ctx = ctx.lock().await;

        let mut id_gen = app.id_gen.lock().await;
        let id = id_gen.generate::<i64>().to_string();
        drop(id_gen);
        // 0x81000000 to 0x81FFFFFF
        let mut handle = None;
        let mut iterations = 0;
        loop {
            if iterations > 5 {
                // Don't keep going...tbd better solution.
                return (StatusCode::INTERNAL_SERVER_ERROR).into_response();
            }
            let possible_handle = (0x81000000u32 as u32..0x81FFFFFF as u32)
                .choose(&mut rand::rngs::OsRng)
                .unwrap();

            let p_handle = PersistentTpmHandle::new(possible_handle).unwrap();
            if !ctx
                .tr_from_tpm_public(tss_esapi::handles::TpmHandle::Persistent(p_handle))
                .is_ok()
            {
                handle = Some(possible_handle);
                break;
            }
            iterations += 1;
        }
        let Some(handle) = handle else { panic!() };
        sqlx::query_as::<_, (String,)>(r#"INSERT INTO kek_store(id,wrapped_kek,persistent_handle) VALUES($1,$2,$3) RETURNING id"#).bind(&id).bind(vec![]).bind(handle).fetch_one(&app.database).await.unwrap();
    }
    (StatusCode::OK).into_response()
}

#[derive(Serialize, Deserialize)]
pub struct UnwrapDEKRequest {}

pub async fn unwrap_dek(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Json(unwrap_dek_req): Json<UnwrapDEKRequest>,
) -> impl IntoResponse {
    (StatusCode::OK).into_response()
}

pub async fn status(ConnectInfo(_client_addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    (StatusCode::OK).into_response()
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let tcti = TctiNameConf::from_environment_variable()
        .unwrap_or(TctiNameConf::Device(Default::default()));
    let mut ctx = Arc::new(Mutex::new(Context::new(tcti).unwrap()));

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
    //         ctx.create(primary.key_handle, key_pub, None, None, None, None)
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
