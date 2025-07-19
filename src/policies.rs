use std::collections::{HashMap, HashSet};

use reqwest::dns::Name;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    app::{App, PolicyRuleTargetAction, ResourceTypes},
    models::{Namespace, Person, PolicyRuleTarget, Project, ResourceAssignment, Role},
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccessAction {
    CreateSecret,
    DeleteSecret,
    UpdateSecret,
    CreateProject,
    DeleteProject,
    UpdateProject,
    CreateNameSpace,
    DeleteNameSpace,
    UpdateNameSpace,
    ManageInstanceUsers,
}

// todo: clean this copy/paste up
impl ToString for AccessAction {
    fn to_string(&self) -> String {
        match self {
            AccessAction::CreateSecret => "create:secret",
            AccessAction::DeleteSecret => "delete:secret",
            AccessAction::UpdateSecret => "update:secret",
            AccessAction::CreateProject => "create:project",
            AccessAction::DeleteProject => "delete:project",
            AccessAction::UpdateProject => "update:project",
            AccessAction::CreateNameSpace => "create:namespace",
            AccessAction::DeleteNameSpace => "delete:namespace",
            AccessAction::UpdateNameSpace => "update:namespace",
            AccessAction::ManageInstanceUsers => "manage:instance:users",
        }
        .to_string()
    }
}

impl TryFrom<String> for AccessAction {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        return Ok(match value.as_str() {
            "create:secret" => Self::CreateSecret,
            "delete:secret" => Self::DeleteSecret,
            "update:secret" => Self::UpdateSecret,
            "create:project" => Self::CreateProject,
            "delete:project" => Self::DeleteProject,
            "update:project" => Self::UpdateProject,
            "create:namespace" => Self::CreateNameSpace,
            "delete:namespace" => Self::DeleteNameSpace,
            "update:namespace" => Self::UpdateNameSpace,
            "manage:instance:users" => Self::ManageInstanceUsers,
            _ => return Err(String::from("Unkown action")),
        });
    }
}

impl Into<String> for AccessAction {
    fn into(self) -> String {
        match self {
            AccessAction::CreateSecret => "create:secret",
            AccessAction::DeleteSecret => "delete:secret",
            AccessAction::UpdateSecret => "update:secret",
            AccessAction::CreateProject => "create:project",
            AccessAction::DeleteProject => "delete:project",
            AccessAction::UpdateProject => "update:project",
            AccessAction::CreateNameSpace => "create:namespace",
            AccessAction::DeleteNameSpace => "delete:namespace",
            AccessAction::UpdateNameSpace => "update:namespace",
            AccessAction::ManageInstanceUsers => "manage:instance:users",
        }
        .to_string()
    }
}

pub fn split(res: String) -> (String, ResourceTypes) {
    let split = res.split(":").collect::<Vec<&str>>();
    let Some(first) = split.get(0) else { panic!() };
    let Some(latter) = split.get(1..) else {
        panic!()
    };
    let r#type: ResourceTypes = ResourceTypes::try_from(*first).unwrap();
    return (latter.join(":").to_string(), r#type);
}

pub async fn check_allowed(
    app: &App,
    namespace: Option<String>,
    project: Option<String>,
    resource: String,
    person: String,
    required_perms: HashSet<AccessAction>,
) -> bool {
    let (resource_ident, resource_type) = split(resource);
    let person = sqlx::query_as::<_, Person>(r#"SELECT * FROM tokaysec.people WHERE id = ($1)"#)
        .bind(&person)
        .fetch_one(&app.database.inner)
        .await
        .unwrap();
    let mut permissions = vec![];
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
        let assigned_role_perms =  sqlx::query_as::<_, PolicyRuleTarget>(r#"SELECT * FROM tokaysec.policy_rule_target WHERE target = ($1) AND target_type = ($2) AND action = 1 AND resource_type = ($3)"#)
            .bind(&role.id).bind("role").bind("perm")
            .fetch_all(&app.database.inner)
            .await
            .unwrap();
        permissions.extend(assigned_role_perms);
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
            ResourceTypes::Person => return id == person.id,
            ResourceTypes::Permission => todo!(),
            ResourceTypes::Role => {
                let role =
                    sqlx::query_as::<_, Role>(r#"SELECT * FROM tokaysec.roles WHERE id = ($1)"#)
                        .bind(&id)
                        .fetch_one(&app.database.inner)
                        .await
                        .unwrap();
                return person_roles.iter().any(|e| e.id == role.id);
            }
            _ => return false,
        }
    };
    info!(
        "\nOperating on:\n\tDeny-> {:?}\n\tUser Roles-> {:?}\n\tUser permissions-> {:?}",
        list, person_roles, permissions
    );
    let present_permissions: HashSet<AccessAction> = permissions
        .into_iter()
        .map(|e| e.resource.try_into().unwrap())
        .collect::<HashSet<AccessAction>>();
    let required_present_intersection = required_perms.intersection(&present_permissions);
    // 1. If any deny, return false
    // 2. If any allow, return true
    for (id, r#type, action) in list {
        let is_okay = check_if_okay(r#type, id).await;
        if let PolicyRuleTargetAction::Deny = action
            && !is_okay
        {
            return false;
        } else if let PolicyRuleTargetAction::Allow = action
            && is_okay
        {
            if !required_present_intersection.eq(&required_perms) {
                println!(
                    "Missing some permissions: {:?}",
                    required_perms
                        .iter()
                        .filter(|e| !present_permissions.contains(e))
                );
                return false;
            }
            return true;
        }
    }
    return false;
}
