use std::collections::HashMap;

use reqwest::dns::Name;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    app::{App, PolicyRuleTargetAction, ResourceTypes},
    models::{Namespace, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
};

#[derive(Debug)]
pub enum AccessAction {
    Manage,
}

pub fn split(res: String) -> (String, ResourceTypes) {
    let split = res.split(":").collect::<Vec<&str>>();
    if let Some(first) = split.get(0)
        && let Some(second) = split.get(1)
    {
        let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
        return (second.to_string(), r#type);
    } else {
        panic!("{:?}", res);
    };
}

pub async fn check_allowed(
    app: &App,
    namespace: Option<String>,
    project: Option<String>,
    resource: String,
    person: String,
    access_action: AccessAction,
) -> bool {
    let (resource_ident, resource_type) = split(resource);
    let person = sqlx::query_as::<_, Person>(r#"SELECT * FROM tokaysec.people WHERE id = ($1)"#)
        .bind(&person)
        .fetch_one(&app.database.inner)
        .await
        .unwrap();
    let mut person_roles = vec![];
    let raw_person_role = sqlx::query_as::<_, ResourceAssignment>(
        r#"SELECT * FROM tokaysec.resource_assignment WHERE assigned_to = ($1) AND assigned_to_type = ($2) AND resource_type = ($3)"#,
    )
    .bind(&person.id)
    .bind(ResourceTypes::Person.to_string())
    .bind(ResourceTypes::Role.to_string())
    .fetch_all(&app.database.inner)
    .await
    .unwrap();
    for role in raw_person_role {
        let role = sqlx::query_as::<_, Role>(r#"SELECT * FROM tokaysec.roles WHERE id = ($1)"#)
            .bind(&role.resource)
            .fetch_one(&app.database.inner)
            .await
            .unwrap();
        person_roles.push(role);
    }
    let mut list = vec![];
    if let Some(namespace) = namespace {
        let namespace =
            sqlx::query_as::<_, Namespace>(r#"SELECT * FROM tokaysec.namespaces WHERE id = ($1)"#)
                .bind(&namespace)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();
        let rules = sqlx::query_as::<_, PolicyRuleTarget>(
                r#"SELECT * FROM tokaysec.policy_rule_target WHERE target = ($1) AND target_type = ($2)"#,
            )
            .bind(&namespace.id).bind(ResourceTypes::Namespace.to_string())
            .fetch_all(&app.database.inner)
            .await
            .unwrap();
        for rule in rules {
            let r#type: ResourceTypes =
                ResourceTypes::try_from(rule.resource_type.as_str()).unwrap();
            match rule.action.into() {
                a @ PolicyRuleTargetAction::Allow | a @ PolicyRuleTargetAction::Deny => {
                    list.push((rule.resource, r#type, a))
                }
                PolicyRuleTargetAction::FallThrough => {
                    unimplemented!("Fall through not implemented.")
                }
            }
        }
    }
    if let Some(project) = project {
        let project =
            sqlx::query_as::<_, Project>(r#"SELECT * FROM tokaysec.projects WHERE id = ($1)"#)
                .bind(&project)
                .fetch_one(&app.database.inner)
                .await
                .unwrap();
        let rules = sqlx::query_as::<_, PolicyRuleTarget>(
                r#"SELECT * FROM tokaysec.policy_rule_target WHERE target = ($1) AND target_type = ($2)"#,
            )
            .bind(&project.id).bind(ResourceTypes::Project.to_string())
            .fetch_all(&app.database.inner)
            .await
            .unwrap();
        for rule in rules {
            let r#type: ResourceTypes =
                ResourceTypes::try_from(rule.resource_type.as_str()).unwrap();
            match rule.action.into() {
                a @ PolicyRuleTargetAction::Allow | a @ PolicyRuleTargetAction::Deny => {
                    list.push((rule.resource, r#type, a))
                }
                PolicyRuleTargetAction::FallThrough => {
                    unimplemented!("Fall through not implemented.")
                }
            }
        }
    }

    let check_if_okay = async |ty: ResourceTypes, id: String| -> bool {
        match ty {
            ResourceTypes::Person => {
                if id == person.id {
                    return false;
                }
            }
            ResourceTypes::Permission => todo!(),
            ResourceTypes::Role => {
                let role =
                    sqlx::query_as::<_, Role>(r#"SELECT * FROM tokaysec.roles WHERE id = ($1)"#)
                        .bind(&id)
                        .fetch_one(&app.database.inner)
                        .await
                        .unwrap();
                if person_roles.iter().any(|e| e.id == role.id) {
                    return false;
                }
            }
            _ => return false,
        }
        return true;
    };
    info!(
        "\nOperating on:\n\tDeny-> {:?}\n\tUser Roles-> {:?}",
        list, person_roles
    );
    // 1. If any deny, return false
    // 2. If any allow, return true
    for (id, r#type, action) in list {
        let not_okay = check_if_okay(r#type, id).await;
        if let PolicyRuleTargetAction::Deny = action
            && !not_okay
        {
            return false;
        } else if let PolicyRuleTargetAction::Allow = action
            && not_okay
        {
            return true;
        }
    }
    return false;
}