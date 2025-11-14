use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetUserEntry {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Cn")]
    pub cn: String,
    #[serde(rename = "Sn")]
    pub sn: String,
    #[serde(rename = "Home_directory")]
    pub home_directory: String,
    #[serde(rename = "Shell")]
    pub shell: String,
    #[serde(rename = "Given_name")]
    pub given_name: String,
    #[serde(rename = "Display_name")]
    pub display_name: String,
    #[serde(rename = "Gid_number")]
    pub gid_number: String,
    #[serde(rename = "Group")]
    pub group: Vec<String>,
    #[serde(rename = "Gecos")]
    pub gecos: String,
}

#[derive(Debug, Serialize)]
pub struct UsersCollection {
    #[serde(rename = "Users")]
    pub users: HashMap<String, GetUserEntry>,
    #[serde(rename = "Length")]
    pub length: usize,
}

// POST /api/chm/user
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "Cn")]
    pub cn: String,
    #[serde(rename = "Sn")]
    pub sn: String,
    #[serde(rename = "Home_directory")]
    pub home_directory: String,
    #[serde(rename = "Shell")]
    pub shell: String,
    #[serde(rename = "Given_name")]
    pub given_name: String,
    #[serde(rename = "Display_name")]
    pub display_name: String,
    #[serde(rename = "Group")]
    pub group: Vec<String>,
    #[serde(rename = "Gecos")]
    pub gecos: String,
}

// PUT /api/chm/user  — 更改整筆（以 uid 做 key）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PutUserEntry {
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "Cn")]
    pub cn: String,
    #[serde(rename = "Sn")]
    pub sn: String,
    #[serde(rename = "Home_directory")]
    pub home_directory: String,
    #[serde(rename = "Shell")]
    pub shell: String,
    #[serde(rename = "Given_name")]
    pub given_name: String,
    #[serde(rename = "Display_name")]
    pub display_name: String,
    #[serde(rename = "Group")]
    pub group: Vec<String>,
    #[serde(rename = "Gecos")]
    pub gecos: String,
}
#[derive(Debug, Deserialize)]
pub struct PutUsersRequest {
    #[serde(flatten)]
    pub data: HashMap<String, PutUserEntry>,
}

// PATCH /api/chm/user
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct PatchUserEntry {
    #[serde(rename = "Password", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub password: Option<String>,
    #[serde(rename = "Cn", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub cn: Option<String>,
    #[serde(rename = "Sn", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub sn: Option<String>,
    #[serde(
        rename = "Home_directory",
        deserialize_with = "chm_cluster_utils::none_if_string_none"
    )]
    pub home_directory: Option<String>,
    #[serde(rename = "Shell", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub shell: Option<String>,
    #[serde(rename = "Given_name", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub given_name: Option<String>,
    #[serde(rename = "Display_name", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub display_name: Option<String>,
    #[serde(rename = "Group")]
    pub group: Option<Vec<String>>,
    #[serde(rename = "Gecos", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub gecos: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatchUsersRequest {
    #[serde(flatten)]
    pub data: HashMap<String, PatchUserEntry>,
}

// DELETE /api/chm/user
#[derive(Debug, Deserialize)]
pub struct DeleteUserRequest {
    #[serde(rename = "uid")]
    pub uid: String,
}
