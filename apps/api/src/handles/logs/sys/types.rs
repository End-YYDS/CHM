use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct SysLogTime {
    #[serde(rename = "Hour")]
    pub hour: i64,
    #[serde(rename = "Min")]
    pub min:  i64,
}

#[derive(Debug, Serialize)]
pub struct SysLogEntry {
    #[serde(rename = "Month")]
    pub month:     String,
    #[serde(rename = "Day")]
    pub day:       i64,
    #[serde(rename = "Time")]
    pub time:      SysLogTime,
    #[serde(rename = "Direction")]
    pub direction: String,
    #[serde(rename = "Type")]
    pub log_type:  String,
    #[serde(rename = "Messages")]
    pub messages:  String,
}

#[derive(Debug, Serialize)]
pub struct SysLogsResponse {
    #[serde(rename = "Logs")]
    pub logs:   HashMap<String, SysLogEntry>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct SysLogQuery {
    #[serde(rename = "Search")]
    pub search:    String,
    #[serde(rename = "Parameter")]
    pub parameter: String,
}
