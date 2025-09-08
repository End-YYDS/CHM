use serde::Serialize;

use crate::{commons::CommonInfo, handles::server::mysql::logs::Logs};

#[derive(Debug, Serialize)]
pub struct MySQLResponse {
    #[serde(flatten)]
    pub common_info:     CommonInfo,
    #[serde(rename = "Connections")]
    pub connections:     i64,
    #[serde(rename = "Databases")]
    pub databases:       i64,
    #[serde(rename = "Queries_per_sec")]
    pub queries_per_sec: f64,
    #[serde(rename = "Logs")]
    pub logs:            Logs,
}
