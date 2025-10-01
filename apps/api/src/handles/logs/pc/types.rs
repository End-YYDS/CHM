use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct PcLogEntry {
    #[serde(rename = "Month")]
    pub month:    String,
    #[serde(rename = "Day")]
    pub day:      i64,
    #[serde(rename = "Time")]
    pub time:     String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Type")]
    pub log_type: String,
    #[serde(rename = "Messages")]
    pub messages: String,
}

#[derive(Debug, Serialize)]
pub struct PcLogsResponse {
    #[serde(rename = "Logs")]
    pub logs:   HashMap<String, PcLogEntry>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct PcsResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, String>, // uuid -> hostname
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct PcRequest {
    #[serde(rename = "Uuid")]
    pub uuid: String,
}

#[derive(Debug, Deserialize)]
pub struct PcLogQuery {
    #[serde(rename = "Uuid")]
    pub uuid:      String,
    #[serde(rename = "Search")]
    pub search:    String,
    #[serde(rename = "Parameter")]
    pub parameter: String,
}
