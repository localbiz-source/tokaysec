use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyAllowed {
    pub people: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyDefineRole {
    pub name: String,
    pub permissions: Option<Vec<String>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyDefinePeople {
    pub roles: Option<Vec<String>>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BasePolciy {
    pub scope: String,
    pub allowed: Option<PolicyAllowed>,
    #[serde(rename(deserialize = "roles"))]
    pub define_roles: Option<Vec<PolicyDefineRole>>,
    #[serde(rename(deserialize = "people"))]
    pub define_people: Option<HashMap<String, PolicyDefinePeople>>,
}
