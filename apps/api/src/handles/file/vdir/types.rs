use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct VdirResponse {
    #[serde(rename = "Path")]
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct DownloadRequest {
    #[serde(rename = "Filename")]
    pub filename: String,
}
