use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

/// 軟體安裝狀態
#[derive(Debug, Serialize, Deserialize, Clone, Copy, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum PackageStatus {
    Installed,
    Notinstall,
}

pub enum PackageActionKind {
    Install,
    Delete,
}

/// 單一套件的資訊
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PackageInfo {
    pub version: String,
    pub status:  PackageStatus,
}

/// 單一 PC 的 Packages
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PcPackages {
    pub packages: HashMap<String, PackageInfo>, // package name -> info
}

/// GET /api/software 回應
#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetSoftwareResponse {
    pub pcs: HashMap<String, PcPackages>, // uuid -> packages
}

/// POST /api/software 請求
#[derive(Debug, Deserialize, Default, ToSchema)]
#[serde(default, deny_unknown_fields, rename_all = "PascalCase")]
pub struct InstallRequest {
    #[serde(rename = "uuid", alias = "Uuid", alias = "UUID")]
    pub uuids:    Vec<String>,
    pub packages: Option<Vec<String>>,
}

/// DELETE /api/software 請求
#[derive(Debug, Deserialize, Default, ToSchema)]
#[serde(default, deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeleteRequest {
    #[serde(rename = "uuid", alias = "Uuid", alias = "UUID")]
    pub uuids:    Vec<String>,
    #[serde(rename = "Package", alias = "Packages", alias = "package")]
    pub packages: Option<Vec<String>>,
}

/// 安裝/刪除的結果
#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PackageActionResult {
    pub installed:    Vec<String>,
    pub notinstalled: Vec<String>,
}

/// POST/DELETE 回應
#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ActionResponse {
    pub packages: HashMap<String, PackageActionResult>,
    pub length:   usize,
}
