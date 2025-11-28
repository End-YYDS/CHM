use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GroupEntry {
    pub groupname: String,
    #[serde(default)]
    pub users:     Vec<String>, // uid.username（字串）
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GroupsCollection {
    pub groups: HashMap<String, GroupEntry>,
}

// POST /api/chm/group
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct CreateGroupRequest {
    pub groupname: String,
    pub users:     Vec<String>,
}

// PUT /api/chm/group
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PutGroupsRequest {
    #[serde(flatten)]
    pub data: HashMap<String, GroupEntry>,
}

// PATCH /api/chm/group
#[derive(Debug, Deserialize, Clone, Default, ToSchema)]
#[serde(deny_unknown_fields, default, rename_all = "PascalCase")]
pub struct PatchGroupEntry {
    #[serde(
        default,
        rename = "Groupname",
        deserialize_with = "chm_cluster_utils::none_if_string_none"
    )]
    pub groupname: Option<String>,
    #[serde(rename = "Users")]
    pub users:     Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PatchGroupsRequest {
    #[serde(flatten)]
    pub groups: HashMap<String, PatchGroupEntry>,
}

// DELETE /api/chm/group
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeleteGroupRequest {
    pub gid: String,
}
