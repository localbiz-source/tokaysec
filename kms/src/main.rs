use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::ConnectInfo,
    response::IntoResponse,
    routing::{get, post},
};
use axum_client_ip::ClientIpSource;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

#[derive(Serialize, Deserialize)]
pub struct UnwrapDEKRequest {}

pub async fn unwrap_dek(
    //State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Json(unwrap_dek_req): Json<UnwrapDEKRequest>,
) -> impl IntoResponse {
    (StatusCode::OK).into_response()
}

pub async fn status(
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    (StatusCode::OK).into_response()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let router: Router<()> = Router::new()
        .route("/unwrap", post(unwrap_dek))
        .route("/status", get(status))
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
