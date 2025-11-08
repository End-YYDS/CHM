use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct RolesResponse {
    #[serde(rename = "Roles")]
    pub roles:  Vec<RoleInfo>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleInfo {
    #[serde(rename = "RoleName")]
    pub name:        String,
    #[serde(rename = "Permissions")]
    pub permissions: i64,
    #[serde(rename = "Color")]
    pub color:       Color,
    #[serde(rename = "Members")]
    pub members:     Vec<String>,
    #[serde(rename = "Length")]
    pub length:      usize,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub enum Color {
    Red,
    Green,
    Blue,
    Yellow,
    Purple,
    Orange,
    Black,
    White,
    #[default]
    Gray,
    Custom(String), // Hex code or RGB
}

#[derive(Debug, Serialize)]
pub struct UsersResponse {
    #[serde(rename = "Users")]
    pub users:  HashMap<String, String>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct RoleDeleteRequest {
    #[serde(rename = "RoleName")]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RolePutResponse {
    #[serde(rename = "RoleName")]
    pub name:    String,
    #[serde(rename = "Members")]
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RolePatchRequest {
    #[serde(rename = "RoleName")]
    pub name:        String,
    #[serde(rename = "Permissions")]
    pub permissions: Option<i64>,
    #[serde(rename = "Color")]
    pub color:       Option<Color>,
}
