use crate::commons::{Date, ResponseResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub enum BackupLocation {
    #[serde(rename = "Local")]
    Local,
    #[serde(rename = "Remote")]
    Remote,
}

#[derive(Debug, Deserialize)]
pub struct BackupRequest {
    #[serde(rename = "Type")]
    pub r#type: BackupLocation,
    #[serde(rename = "Name")]
    pub name:   String,
}

#[derive(Debug, Serialize)]
pub struct BackupResponse {
    #[serde(flatten)]
    pub inner:        ResponseResult,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Id")] // None -> Remote
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "DownloadUrl")] // None -> Remote
    pub download_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InnerGetBackupResponse {
    #[serde(rename = "Name")]
    pub name:  String,
    #[serde(flatten)]
    pub inner: Date,
}
fn default_limit() -> usize {
    5
}

#[derive(Debug, Deserialize)]
pub struct GetBackupsRequest {
    #[serde(alias = "Limit", alias = "limit", default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct GetBackupsResponse {
    #[serde(rename = "Backups")]
    pub backups: Vec<InnerGetBackupResponse>,
    #[serde(rename = "Length")]
    pub length:  usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "Type")]
pub enum ReductionRequest {
    Remote {
        #[serde(rename = "Name")]
        name: String,
    },
    Local {
        #[serde(rename = "File")]
        file: String,
    },
}
