use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsPair {
    #[serde(rename = "Primary")]
    pub primary:   String,
    #[serde(rename = "Secondary")]
    pub secondary: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PcDns {
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "DNS")]
    pub dns:      DnsPair,
}

#[derive(Debug, Serialize)]
pub struct GetAllDnsResponse {
    #[serde(rename = "Pcs")]
    pub pcs: HashMap<String, PcDns>, // uuid -> { Hostname, DNS }
}

// PATCH /api/network/dns （更改 Hostname）
#[derive(Debug, Deserialize)]
pub struct PatchHostnameRequest {
    #[serde(rename = "Uuid")]
    pub uuid: String, /* 規格註解寫「// hostname」，此處視為要修改哪台的 hostname
                       * 若之後規格改成同時提供新 Hostname，可新增:
                       * #[serde(rename = "Hostname")]
                       * pub hostname: String, */
}

// PUT /api/network/dns （更改 DNS 伺服器）
#[derive(Debug, Deserialize)]
pub struct PutDnsRequest {
    #[serde(rename = "Primary")]
    pub primary:   String,
    #[serde(rename = "Secondary")]
    pub secondary: String,
}
