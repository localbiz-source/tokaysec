use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    response::IntoResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::Value;

use crate::{
    app::App,
    models::{Namespace, Project, ResourceAssignment},
    stores::RetrievedSecretData,
};
/*
justin@Mac tokaysecapp % curl http://localhost:2323/v1/namespaces
[{"id":"7352140924266221570","name":"default_namespace","added_when":"2025-07-19T01:03:12.518871Z","created_by":"7352140924253638657","last_updated":"2025-07-19T01:03:12.518871Z"}]%                                                                                                                                 
justin@Mac tokaysecapp % curl http://localhost:2323/v1/namespaces/7352140924266221570/projects
[{"id":"7352141003882500096","name":"default_projcet","kek_id":"7352140924433993728","namespace":"7352140924266221570","added_when":"2025-07-19T01:03:31.500473Z"},{"id":"7352141083272286208","name":"top_secret_project","kek_id":"7352141004062855168","namespace":"7352140924266221570","added_when":"2025-07-19T01:03:50.428022Z"}]%     
*/
pub async fn list_namespaces(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let namespaces = sqlx::query_as::<_, Namespace>(r#"SELECT * FROM tokaysec.namespaces"#)
        .fetch_all(&app.database.inner)
        .await
        .unwrap();
    (StatusCode::OK, serde_json::to_string(&namespaces).unwrap())
}

pub async fn list_namespace_projects(
    State(app): State<App>,
    ConnectInfo(_client_addr): ConnectInfo<SocketAddr>,
    Path(namespace): Path<String>,
) -> impl IntoResponse {
    let projects: Vec<Project> =
        sqlx::query_as::<_, Project>(r#"SELECT * FROM tokaysec.projects WHERE namespace = ($1)"#)
            .bind(&namespace)
            .fetch_all(&app.database.inner)
            .await
            .unwrap();
    (StatusCode::OK, serde_json::to_string(&projects).unwrap())
}

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
