use serde::Serialize;

use crate::{commons::CommonInfo, handles::server::squid::logs::Logs};

#[derive(Debug, Serialize)]
pub struct SquidResponse {
    // Define the fields for the SquidResponse struct
    #[serde(flatten)]
    pub common:             CommonInfo,
    #[serde(rename = "Connections")]
    pub connections:        i64,
    #[serde(rename = "Cache_Hits")]
    pub cache_hits:         i64,
    #[serde(rename = "Cache_Misses")]
    pub cache_misses:       i64,
    #[serde(rename = "Requests_Processed")]
    pub requests_processed: i64,
    #[serde(rename = "Logs")]
    pub logs:               Logs,
}
