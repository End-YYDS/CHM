use chm_cluster_utils::none_if_string_none;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct InfoCounts {
    #[serde(rename = "Safe")]
    pub safe: i64,
    #[serde(rename = "Warn")]
    pub warn: i64,
    #[serde(rename = "Dang")]
    pub dang: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ClusterSummary {
    #[serde(rename = "Cpu")]
    pub cpu:    f64,
    #[serde(rename = "Memory")]
    pub memory: f64,
    #[serde(rename = "Disk")]
    pub disk:   f64,
}

#[derive(Debug, Serialize)]
pub struct GetAllInfoResponse {
    #[serde(rename = "Info")]
    pub info:    InfoCounts,
    #[serde(rename = "Cluster")]
    pub cluster: ClusterSummary,
}

/// POST /api/info/get
#[derive(Debug, Deserialize)]
pub struct InfoGetRequest {
    /// "info" 或 "cluster"
    #[serde(rename = "Zone")]
    pub zone:   Zone,
    /// safe / warn / dang / Cpu / Memory / Disk
    #[serde(rename = "Target")]
    pub target: Target,
    /// None 代表全部；Some(uuid) 代表指定主機
    #[serde(rename = "Uuid", default, deserialize_with = "none_if_string_none")]
    pub uuid:   Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    info,
    cluster,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum Target {
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "dang")]
    Dang,
    #[serde(rename = "Cpu")]
    Cpu,
    #[serde(rename = "Memory")]
    Memory,
    #[serde(rename = "Disk")]
    Disk,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct PcMetrics {
    #[serde(rename = "Cpu")]
    pub cpu:    f64,
    #[serde(rename = "Memory")]
    pub memory: f64,
    #[serde(rename = "Disk")]
    pub disk:   f64,
}

#[derive(Debug, Serialize)]
pub struct InfoGetResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, PcMetrics>,
    #[serde(rename = "Length")]
    pub length: usize,
}
