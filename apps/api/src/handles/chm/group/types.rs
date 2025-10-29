use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupEntry {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Users", default)]
    pub users:     Vec<String>, // uid.username（字串）
}

#[derive(Debug, Serialize)]
pub struct GroupsCollection {
    #[serde(rename = "Groups")]
    pub groups: HashMap<String, GroupEntry>,
}

// POST /api/chm/group
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Users")]
    pub users:     Vec<String>,
}

// PUT /api/chm/group
#[derive(Debug, Deserialize)]
pub struct PutGroupsRequest {
    // pub gid01: Option<GroupEntry>,
    #[serde(flatten)]
    pub data: HashMap<String, GroupEntry>,
}

// PATCH /api/chm/group
#[derive(Debug, Deserialize, Clone, Default)]
#[serde()]
pub struct PatchGroupEntry {
    #[serde(default, rename = "Groupname", deserialize_with = "chm_cluster_utils::none_if_string_none")]
    pub groupname: Option<String>,
    #[serde(rename = "Users")]
    pub users:     Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PatchGroupsRequest {
    // pub gid01: Option<PatchGroupEntry>,
    // 或改為 HashMap<String, PatchGroupEntry>
    #[serde(flatten)]
    pub groups: HashMap<String, PatchGroupEntry>,
}

// DELETE /api/chm/group
#[derive(Debug, Deserialize)]
pub struct DeleteGroupRequest {
    #[serde(rename = "gid")]
    pub gid: String,
}
