use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    response::IntoResponse,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::app::App;

pub async fn ui_reqs(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(store): Path<String>,
) -> impl IntoResponse {
    let stores = app.stores.clone();
    let stores_read = stores.read().await;
    let store = stores_read.get(&store).unwrap().to_owned();
    (
        StatusCode::OK,
        serde_json::to_string(&store.ui_reqs()).unwrap(),
    )
}

pub async fn retrieve(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(store): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let stores = app.stores.clone();
    let stores_read = stores.read().await;
    let kv_store = stores_read.get(&store).unwrap().to_owned();
    let kek_provider = app.kek_provider.to_owned();
    let kek_provider = (*kek_provider).as_ref();
    kv_store.retrieve(&app, query, kek_provider).await;
    (StatusCode::OK, json!({}).to_string())
}

pub async fn store(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(store): Path<String>,
    Json(store_req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let stores = app.stores.clone();
    let stores_read = stores.read().await;
    let kv_store = stores_read.get(&store).unwrap().to_owned();
    let kek_provider = app.kek_provider.to_owned();
    let kek_provider = (*kek_provider).as_ref();
    let admin_id = app
        .get_config_value::<String>("admin_account_id")
        .await
        .unwrap();
    let admin_user: &str = admin_id.as_str();
    println!("{:?}", store_req);
    kv_store
        .store(
            &app,
            serde_json::from_value::<String>(store_req["project"].to_owned()).unwrap(),
            kek_provider,
            store_req,
            admin_user,
        )
        .await;

    (StatusCode::OK, json!({}).to_string())
}
