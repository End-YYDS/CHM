use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 進程條目
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ProcessEntry {
    #[serde(rename = "Status")]
    pub status: bool,
    #[serde(rename = "Boot")]
    pub boot:   bool,
}

/// /api/process/all 單台電腦的封裝
#[derive(Debug, Serialize)]
pub struct PcProcess {
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Process")]
    pub process:  HashMap<String, ProcessEntry>, // pname -> entry
    #[serde(rename = "Length")]
    pub length:   usize,
}

/// /api/process/all 回應
#[derive(Debug, Serialize)]
pub struct GetAllProcessResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, PcProcess>, // uuid -> PcProcess
    #[serde(rename = "Length")]
    pub length: usize,
}

/// /api/process/one 請求
#[derive(Debug, Deserialize)]
pub struct OneProcessRequest {
    #[serde(rename = "Uuid")]
    pub uuid: String,
}

/// /api/process/one 回應
#[derive(Debug, Serialize)]
pub struct OneProcessResponse {
    #[serde(rename = "Process")]
    pub process: HashMap<String, ProcessEntry>, // pname -> entry
    #[serde(rename = "Length")]
    pub length:  usize,
}

/// 動作類請求：start/stop/restart/enable/disable/...
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    #[serde(rename = "Uuid")]
    pub uuid:    String,
    #[serde(rename = "Process")]
    pub process: String,
}
