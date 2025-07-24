use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    response::IntoResponse,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use reqwest::{StatusCode, header};
use ring::rand::SecureRandom as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Value;

use crate::{
    app::App,
    models::{Namespace, Project, ResourceAssignment},
    stores::RetrievedSecretData,
};
use openidconnect::{
    AccessTokenHash, AdditionalProviderMetadata, AuthenticationFlow, AuthorizationCode, Client,
    ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeVerifier, ProviderMetadata, RedirectUrl,
    RevocationErrorResponseType, RevocationUrl, Scope, StandardErrorResponse,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse as _,
    core::{CoreAuthPrompt, CoreAuthenticationFlow, CoreGenderClaim, CoreJwsSigningAlgorithm},
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

/*

https://staging.jiternal.com/api/v1/auth/finish/google?state=a9ypVQ-RhTVOxruDPsECRA&code=4%2F0AVMBsJix_Pwxa4DxtZTj6GAV28Xrrm83dIMe_c9tp3QeJR37rKu5HGzo1fyULlmA89UWyw&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+openid&authuser=0&prompt=consent

*/

#[derive(Serialize, Deserialize)]
pub struct FinishOIDCAuthSessionQuery {
    pub code: String,
    pub state: String,
}

#[derive(Serialize, Deserialize)]
pub struct TempOIDCAuthSessionRedisData {
    pub csrf_state: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
    pub nonce: Nonce,
}

pub async fn get_login_options(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let oidc_providers = app.oidc.clone();
    let oidc_providers_read = oidc_providers.read().await;
    let mapped_providers = oidc_providers_read
        .iter()
        .map(|e| {
            json!({
                "name": e.0,
                "url": format!("https://staging.jiternal.com/api/v1/auth/start/oidc/{}", e.0)
            })
        })
        .collect::<Vec<serde_json::Value>>();
    (
        StatusCode::OK,
        json!({
            "oidc": mapped_providers
        })
        .to_string(),
    )
}
pub async fn finish_oidc_auth_session(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    cookie_jar: CookieJar,
    Path(oidc): Path<String>,
    Query(finish_oidc_auth_sessiin_query): Query<FinishOIDCAuthSessionQuery>,
) -> impl IntoResponse {
    let oidc_providers = app.oidc.clone();
    let oidc_providers_read = oidc_providers.read().await;
    let specific_provider = oidc_providers_read.get(&oidc).unwrap();
    let Some(temp_auth_session_key) = cookie_jar.get("__temp_auth_session_key") else {
        println!("1");
        panic!("error1");
    };
    let mut redis_conn = app.database.redis.clone();
    let temp_auth_session_key_value = String::from_utf8(
        base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(temp_auth_session_key.value())
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let Ok(Some(toasrd)) = redis_conn
        .get_del::<String, Option<String>>(format!("tokaysec:task:{}", temp_auth_session_key_value))
        .await
    else {
        println!("2");
        panic!("error 2");
    };
    let temp_oidc_auth_session_redis_data =
        serde_json::from_str::<TempOIDCAuthSessionRedisData>(&toasrd).unwrap();
    let code = AuthorizationCode::new(finish_oidc_auth_sessiin_query.code);
    let token_response = specific_provider
        .client
        .exchange_code(code)
        .unwrap()
        // Set the PKCE code verifier.
        .set_pkce_verifier(temp_oidc_auth_session_redis_data.pkce_verifier)
        .request_async(&specific_provider.http)
        .await
        .unwrap();

    let id_token = token_response
        .id_token()
        .ok_or_else(|| panic!("Server did not return an ID token"))
        .unwrap();
    let id_token_verifier = specific_provider.client.id_token_verifier();
    let claims = id_token
        .claims(&id_token_verifier, &temp_oidc_auth_session_redis_data.nonce)
        .unwrap();

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg().unwrap(),
            id_token.signing_key(&id_token_verifier).unwrap(),
        )
        .unwrap();
        if actual_access_token_hash != *expected_access_token_hash {
            panic!("Invalid access token");
        }
    }

    println!(
        "User {} with e-mail address {} has authenticated successfully",
        claims.subject().as_str(),
        claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>"),
    );
    (StatusCode::OK, json!({}).to_string())
}

pub async fn start_oidc_auth_session(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(oidc): Path<String>,
) -> impl IntoResponse {
    let oidc_providers = app.oidc.clone();
    let oidc_providers_read = oidc_providers.read().await;
    let specific_provider = oidc_providers_read.get(&oidc).unwrap();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = specific_provider
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(
            specific_provider
                .scopes
                .iter()
                .map(|e| Scope::new(e.to_owned())),
        )
        .set_pkce_challenge(pkce_challenge)
        .url();
    let toasrd = TempOIDCAuthSessionRedisData {
        csrf_state,
        nonce,
        pkce_verifier,
    };
    let mut redis_conn = app.database.redis.clone();
    let temp_auth_session_key = {
        let mut temp_auth_session_key: [u8; 64] = [0; 64];
        let sr: ring::rand::SystemRandom = ring::rand::SystemRandom::new();
        sr.fill(&mut temp_auth_session_key).unwrap();
        hex::encode(temp_auth_session_key)
    };
    if redis_conn
        .set_ex::<String, String, Option<String>>(
            format!("tokaysec:task:{}", temp_auth_session_key),
            serde_json::to_string(&toasrd).unwrap(),
            900,
        )
        .await
        .unwrap()
        .is_none()
    {
        panic!("value not set?")
    }
    let temp_auth_session_key = BASE64_URL_SAFE_NO_PAD.encode(temp_auth_session_key);
    let mut temp_auth_session_key_cookie =
        Cookie::new("__temp_auth_session_key", temp_auth_session_key);
    temp_auth_session_key_cookie.set_path("/");
    let mut now = time::OffsetDateTime::now_utc();
    now += time::Duration::minutes(15);
    temp_auth_session_key_cookie.set_expires(now);
    temp_auth_session_key_cookie.set_secure(true);
    temp_auth_session_key_cookie.set_http_only(true);
    temp_auth_session_key_cookie.set_same_site(SameSite::Lax);
    temp_auth_session_key_cookie.set_max_age(time::Duration::minutes(15));

    (
        StatusCode::OK,
        [(header::SET_COOKIE, temp_auth_session_key_cookie.to_string())],
        json!({ "url": auth_url.to_string()}).to_string(),
    )
}
/*

            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            let (auth_url, csrf_token, nonce) = client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scopes(
                    oidc_provider
                        .scopes
                        .iter()
                        .map(|e| Scope::new(e.to_owned())),
                )
                .set_pkce_challenge(pkce_challenge)
                .url();
*/
