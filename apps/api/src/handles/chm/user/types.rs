use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetUserEntry {
    pub username:       String,
    pub cn:             String,
    pub sn:             String,
    pub home_directory: String,
    pub shell:          String,
    pub given_name:     String,
    pub display_name:   String,
    pub gid_number:     String,
    pub group:          Vec<String>,
    pub gecos:          String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct UsersCollection {
    pub users:  HashMap<String, GetUserEntry>,
    pub length: usize,
}

// POST /api/chm/user
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct CreateUserRequest {
    pub username:       String,
    pub password:       String,
    pub cn:             String,
    pub sn:             String,
    pub home_directory: String,
    pub shell:          String,
    pub given_name:     String,
    pub display_name:   String,
    pub group:          Vec<String>,
    pub gecos:          String,
}

// PUT /api/chm/user  — 更改整筆（以 uid 做 key）
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PutUserEntry {
    pub password:       String,
    pub cn:             String,
    pub sn:             String,
    pub home_directory: String,
    pub shell:          String,
    pub given_name:     String,
    pub display_name:   String,
    pub group:          Vec<String>,
    pub gecos:          String,
}
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PutUsersRequest {
    #[serde(flatten)]
    pub data: HashMap<String, PutUserEntry>,
}

// PATCH /api/chm/user
#[derive(Debug, Deserialize, Clone, Default, ToSchema)]
#[serde(default, rename_all = "PascalCase")]
pub struct PatchUserEntry {
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub password:       Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub cn:             Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub sn:             Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub home_directory: Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub shell:          Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub given_name:     Option<String>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub display_name:   Option<String>,
    pub group:          Option<Vec<String>>,
    #[serde(deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub gecos:          Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct PatchUsersRequest {
    #[serde(flatten)]
    pub data: HashMap<String, PatchUserEntry>,
}

// DELETE /api/chm/user
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeleteUserRequest {
    pub uid: String,
}
