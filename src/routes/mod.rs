use axum::{
    Router,
    routing::{get, post},
};
use axum_client_ip::ClientIpSource;
use reqwest::Method;

use crate::{
    app::App,
    routes::{
        projects::{list_namespace_projects, list_namespaces, load_secrets},
        stores::{retrieve, store, ui_reqs},
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
        .route("/{store}", get(retrieve))
        .route("/{store}/uireqs", get(ui_reqs));
    let projects = Router::new().route("/secrets", get(load_secrets));
    let namespaces = Router::new()
        .route("/", get(list_namespaces))
        .route("/{namespace}/projects", get(list_namespace_projects));
    let v1 = Router::new()
        .nest("/store", stores)
        .nest("/projects/{project}", projects)
        .nest("/namespaces", namespaces);
    let global_router = Router::new()
        .nest("/v1", v1)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(ClientIpSource::RightmostXForwardedFor.into_extension())
        .with_state(app);
    return global_router;
}
