use crate::commons::{Date, ResponseResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum BackupLocation {
    Local,
    Remote,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct BackupRequest {
    pub r#type: BackupLocation,
    pub name:   String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct BackupResponse {
    #[serde(flatten)]
    pub inner:        ResponseResult,
    #[serde(skip_serializing_if = "Option::is_none")] // None -> Remote
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] // None -> Remote
    pub download_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct InnerGetBackupResponse {
    pub name:  String,
    #[serde(flatten)]
    pub inner: Date,
}
fn default_limit() -> usize {
    5
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetBackupsRequest {
    #[serde(alias = "Limit", alias = "limit", default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetBackupsResponse {
    pub backups: Vec<InnerGetBackupResponse>,
    pub length:  usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase", tag = "Type")]
pub enum ReductionRequest {
    Remote { name: String },
    Local { file: String },
}
