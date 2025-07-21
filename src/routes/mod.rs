use axum::{
    Router,
    routing::{get, post},
};
use axum_client_ip::ClientIpSource;
use reqwest::Method;

use crate::{
    app::App,
    routes::{
        projects::load_secrets,
        stores::{retrieve, store},
    },
};
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};

pub mod projects;
pub mod stores;

pub async fn generate_routers(app: App) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let stores = Router::new()
        .route("/{store}", post(store))
        .route("/{store}", get(retrieve));
    let projects = Router::new().route("/secrets", get(load_secrets));
    let v1 = Router::new()
        .nest("/store", stores)
        .nest("/projects/{project}", projects);
    let global_router = Router::new()
        .nest("/v1", v1)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(ClientIpSource::RightmostXForwardedFor.into_extension())
        .with_state(app);
    return global_router;
}
