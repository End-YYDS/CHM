use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserEntry {
    #[serde(rename = "Username")]
    pub username:       String,
    #[serde(rename = "Group", default)]
    pub group:          Vec<String>,
    #[serde(rename = "Home_directory")]
    pub home_directory: String,
    #[serde(rename = "Shell")]
    pub shell:          String,
}

#[derive(Debug, Serialize)]
pub struct UsersCollection {
    #[serde(rename = "Users")]
    pub users:  HashMap<String, UserEntry>,
    #[serde(rename = "Length")]
    pub length: usize,
}

// POST /api/chm/user
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    #[serde(rename = "Username")]
    pub username:       String,
    #[serde(rename = "Group")]
    pub group:          Vec<String>,
    #[serde(rename = "Home_directory")]
    pub home_directory: String,
    #[serde(rename = "Shell")]
    pub shell:          String,
}

// PUT /api/chm/user  — 更改整筆（以 uid 做 key）
#[derive(Debug, Deserialize)]
pub struct PutUsersRequest {
    // pub uid01: Option<UserEntry>,
    // 若要接受任意 uid，建議改成 HashMap<String, UserEntry>，如下：
    #[serde(flatten)]
    pub data: HashMap<String, UserEntry>,
}

// PATCH /api/chm/user  — 單一內容可選
#[derive(Debug, Deserialize, Clone, Default)]
pub struct PatchUserEntry {
    #[serde(rename = "Username")]
    pub username:       Option<String>,
    #[serde(rename = "Group")]
    pub group:          Option<Vec<String>>,
    #[serde(rename = "Home_directory")]
    pub home_directory: Option<String>,
    #[serde(rename = "Shell")]
    pub shell:          Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatchUsersRequest {
    // pub uid01: Option<PatchUserEntry>,
    #[serde(flatten)]
    pub data: HashMap<String, PatchUserEntry>,
}

// DELETE /api/chm/user
#[derive(Debug, Deserialize)]
pub struct DeleteUserRequest {
    #[serde(rename = "uid")]
    pub uid: String,
}
