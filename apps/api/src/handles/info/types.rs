use chm_cluster_utils::none_if_string_none;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, ToSchema)]
pub struct InfoCounts {
    #[serde(rename = "Safe")]
    pub safe: i64,
    #[serde(rename = "Warn")]
    pub warn: i64,
    #[serde(rename = "Dang")]
    pub dang: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, ToSchema)]
pub struct ClusterSummary {
    #[serde(rename = "Cpu")]
    pub cpu:    f64,
    #[serde(rename = "Memory")]
    pub memory: f64,
    #[serde(rename = "Disk")]
    pub disk:   f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GetAllInfoResponse {
    #[serde(rename = "Info")]
    pub info:    InfoCounts,
    #[serde(rename = "Cluster")]
    pub cluster: ClusterSummary,
}

/// POST /api/info/get
#[derive(Debug, Deserialize, ToSchema)]
pub struct InfoGetRequest {
    /// safe / warn / dang
    #[serde(rename = "Target")]
    pub target: Option<Target>,
    /// None 代表全部；Some(uuid) 代表指定主機
    #[serde(rename = "Uuid", default, deserialize_with = "none_if_string_none")]
    pub uuid:   Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub enum Target {
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "dang")]
    Dang,
}

#[derive(Debug, Serialize, Clone, Copy, Default, ToSchema)]
pub struct PcMetrics {
    #[serde(rename = "Cpu")]
    pub cpu:         f64,
    #[serde(rename = "Memory")]
    pub memory:      f64,
    #[serde(rename = "Disk")]
    pub disk:        f64,
    #[serde(rename = "Cpu_status")]
    pub cpu_status:  StatusLabel,
    #[serde(rename = "Mem_status")]
    pub mem_status:  StatusLabel,
    #[serde(rename = "Disk_status")]
    pub disk_status: StatusLabel,
}

#[derive(Debug, Serialize, Clone, Copy, Default, ToSchema)]
pub enum StatusLabel {
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "dang")]
    Dang,
    #[serde(rename = "unknown")]
    #[default]
    Unknown,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InfoGetResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, PcMetrics>,
    #[serde(rename = "Length")]
    pub length: usize,
}
