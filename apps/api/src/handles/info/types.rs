use chm_cluster_utils::none_if_string_none;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct InfoCounts {
    pub safe: i64,
    pub warn: i64,
    pub dang: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ClusterSummary {
    pub cpu:    f64,
    pub memory: f64,
    pub disk:   f64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetAllInfoResponse {
    pub info:    InfoCounts,
    pub cluster: ClusterSummary,
}

/// POST /api/info/get
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct InfoGetRequest {
    /// safe / warn / dang
    pub target: Option<Target>,
    /// None 代表全部；Some(uuid) 代表指定主機
    #[serde(default, deserialize_with = "none_if_string_none")]
    pub uuid:   Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum Target {
    Safe,
    Warn,
    Dang,
}

#[derive(Debug, Serialize, Clone, Copy, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PcMetrics {
    pub cpu:         f64,
    pub memory:      f64,
    pub disk:        f64,
    pub cpu_status:  StatusLabel,
    pub mem_status:  StatusLabel,
    pub disk_status: StatusLabel,
}

#[derive(Debug, Serialize, Clone, Copy, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum StatusLabel {
    Safe,
    Warn,
    Dang,
    #[default]
    Unknown,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct InfoGetResponse {
    pub pcs:    HashMap<String, PcMetrics>,
    pub length: usize,
}
