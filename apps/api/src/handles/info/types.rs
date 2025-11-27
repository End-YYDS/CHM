use chm_cluster_utils::none_if_string_none;
use chm_grpc::restful;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub struct InfoCounts {
    #[serde(rename = "Safe")]
    pub safe: i64,
    #[serde(rename = "Warn")]
    pub warn: i64,
    #[serde(rename = "Dang")]
    pub dang: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
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
    /// safe / warn / dang
    #[serde(rename = "Target")]
    pub target: Option<Target>,
    /// None 代表全部；Some(uuid) 代表指定主機
    #[serde(rename = "Uuid", default, deserialize_with = "none_if_string_none")]
    pub uuid:   Option<String>,
}

#[derive(Debug, Deserialize)]
pub enum Target {
    #[serde(rename = "safe")]
    Safe,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "dang")]
    Dang,
}

#[derive(Debug, Serialize, Clone, Copy, Default)]
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

impl From<restful::InfoCounts> for InfoCounts {
    fn from(value: restful::InfoCounts) -> Self {
        Self { safe: value.safe, warn: value.warn, dang: value.dang }
    }
}

impl From<restful::ClusterSummary> for ClusterSummary {
    fn from(value: restful::ClusterSummary) -> Self {
        Self { cpu: value.cpu, memory: value.memory, disk: value.disk }
    }
}

impl From<restful::PcMetrics> for PcMetrics {
    fn from(value: restful::PcMetrics) -> Self {
        Self { cpu: value.cpu, memory: value.memory, disk: value.disk }
    }
}

impl From<restful::GetAllInfoResponse> for GetAllInfoResponse {
    fn from(resp: restful::GetAllInfoResponse) -> Self {
        Self {
            info:    resp.info.map(InfoCounts::from).unwrap_or_default(),
            cluster: resp.cluster.map(ClusterSummary::from).unwrap_or_default(),
        }
    }
}

impl From<restful::GetInfoResponse> for InfoGetResponse {
    fn from(resp: restful::GetInfoResponse) -> Self {
        let pcs = resp.pcs.into_iter().map(|(k, v)| (k, PcMetrics::from(v))).collect();
        Self { pcs, length: resp.length as usize }
    }
}

impl From<Target> for restful::Target {
    fn from(value: Target) -> Self {
        match value {
            Target::Safe => restful::Target::Safe,
            Target::Warn => restful::Target::Warn,
            Target::Dang => restful::Target::Dang,
        }
    }
}
