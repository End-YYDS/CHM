use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct PcsResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, String>, // uuid -> hostname
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct GetOneRequest {
    #[serde(rename = "uuid")]
    pub uuid: UuidDir,
}

#[derive(Debug, Deserialize)]
pub struct UuidDir {
    #[serde(rename = "Directory")]
    pub directory: String,
}

#[derive(Debug, Serialize)]
pub struct FileEntry {
    #[serde(rename = "Size")]
    pub size:     f64,
    #[serde(rename = "Unit")]
    pub unit:     FileUnit,
    #[serde(rename = "Owner")]
    pub owner:    String,
    #[serde(rename = "Mode")]
    pub mode:     String,
    #[serde(rename = "Modified")]
    pub modified: String,
}

#[derive(Debug, Serialize)]
pub enum FileUnit {
    #[serde(rename = "B")]
    B,
    #[serde(rename = "KB")]
    KB,
    #[serde(rename = "MB")]
    MB,
    #[serde(rename = "GB")]
    GB,
}

#[derive(Debug, Serialize)]
pub struct FilesResponse {
    #[serde(rename = "Files")]
    pub files:  HashMap<String, FileEntry>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct DownloadRequest {
    #[serde(rename = "Uuid")]
    pub uuid:     String,
    #[serde(rename = "Filename")]
    pub filename: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    #[serde(rename = "Uuid")]
    pub uuid: String,
}
