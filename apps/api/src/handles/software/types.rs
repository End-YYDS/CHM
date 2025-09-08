use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 軟體安裝狀態
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum PackageStatus {
    #[serde(rename = "Installed")]
    Installed,
    #[serde(rename = "Notinstall")]
    Notinstall,
}

/// 單一套件的資訊
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageInfo {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Status")]
    pub status:  PackageStatus,
}

/// 單一 PC 的 Packages
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PcPackages {
    #[serde(rename = "Packages")]
    pub packages: HashMap<String, PackageInfo>, // package name -> info
}

/// GET /api/software 回應
#[derive(Debug, Serialize)]
pub struct GetSoftwareResponse {
    #[serde(rename = "Pcs")]
    pub pcs: HashMap<String, PcPackages>, // uuid -> packages
}

/// POST /api/software 請求
#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    #[serde(rename = "uuid")]
    pub uuids:    Vec<String>,
    #[serde(rename = "Packages")]
    pub packages: Vec<String>,
}

/// DELETE /api/software 請求
#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    #[serde(rename = "uuid")]
    pub uuids:    Vec<String>,
    #[serde(rename = "Package")]
    pub packages: Vec<String>,
}

/// 安裝/刪除的結果
#[derive(Debug, Serialize)]
pub struct PackageActionResult {
    #[serde(rename = "Installed")]
    pub installed:    Vec<String>,
    #[serde(rename = "Notinstalled")]
    pub notinstalled: Vec<String>,
}

/// POST/DELETE 回應
#[derive(Debug, Serialize)]
pub struct ActionResponse {
    #[serde(rename = "Packages")]
    pub packages: HashMap<String, PackageActionResult>, // package -> result
    #[serde(rename = "Length")]
    pub length:   usize,
}
