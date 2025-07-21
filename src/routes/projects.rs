use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    response::IntoResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::Value;

use crate::{app::App, models::ResourceAssignment, stores::RetrievedSecretData};

pub async fn load_secrets(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(project): Path<String>,
) -> impl IntoResponse {
    let mut secrets: Vec<serde_json::Value> = vec![];
    let assignees = sqlx::query_as::<_, ResourceAssignment>(
        r#"SELECT * FROM tokaysec.resource_assignment WHERE assigned_to = ($1) AND assigned_to_type = 'proj' AND resource_type = 'scrt'"#
    ).bind(&project).fetch_all(&app.database.inner).await.unwrap();
    let stores = app.stores.clone();
    let stores_read = stores.read().await;
    for assignee in assignees {
        let split = assignee.resource.split(":").collect::<Vec<&str>>();
        let (store, id) = if let Some(store) = split.get(0)
            && let Some(id) = split.get(1)
        {
            (*store, *id)
        } else {
            continue;
        };

        let _store = stores_read.get(store).unwrap().to_owned();
        let stored_data = _store.get(&app, &id).await;
        secrets.push(json!({
            "id": stored_data.id,
            "name": stored_data.name,
            "store_used": store
        }));
    }
    (StatusCode::OK, serde_json::to_string(&secrets).unwrap())
}
