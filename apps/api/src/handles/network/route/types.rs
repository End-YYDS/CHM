use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteItem {
    #[serde(rename = "Via")]
    pub via:    String,
    #[serde(rename = "Dev")]
    pub dev:    String,
    #[serde(rename = "Proto")]
    pub proto:  String,
    #[serde(rename = "Metric")]
    pub metric: i64,
    #[serde(rename = "Scope")]
    pub scope:  String,
    #[serde(rename = "Src")]
    pub src:    String,
}

#[derive(Debug, Serialize)]
pub struct PcRoutes {
    #[serde(rename = "Routes")]
    pub routes: HashMap<String, RouteItem>, // destination -> item
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct GetAllRouteResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, PcRoutes>, // uuid -> routes
    #[serde(rename = "Length")]
    pub length: usize,
}

// POST /api/network/route
#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Via")]
    pub via:         String,
    #[serde(rename = "Dev")]
    pub dev:         String,
    #[serde(rename = "Proto")]
    pub proto:       String,
    #[serde(rename = "Metric")]
    pub metric:      i64,
    #[serde(rename = "Scope")]
    pub scope:       String,
    #[serde(rename = "Src")]
    pub src:         String,
}

// DELETE /api/network/route
#[derive(Debug, Deserialize)]
pub struct DeleteRouteRequest {
    #[serde(rename = "Destination")]
    pub destination: String,
}

// PATCH 單欄
#[derive(Debug, Deserialize)]
pub enum PatchField {
    #[serde(rename = "Via")]
    Via,
    #[serde(rename = "Dev")]
    Dev,
    #[serde(rename = "Proto")]
    Proto,
    #[serde(rename = "Metric")]
    Metric,
    #[serde(rename = "Scope")]
    Scope,
    #[serde(rename = "Src")]
    Src,
}

#[derive(Debug, Deserialize)]
pub struct PatchRouteRequest {
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Type")]
    pub field:       PatchField,
    // 值（僅需提供對應欄位）
    #[serde(rename = "Via")]
    pub via:         Option<String>,
    #[serde(rename = "Dev")]
    pub dev:         Option<String>,
    #[serde(rename = "Proto")]
    pub proto:       Option<String>,
    #[serde(rename = "Metric")]
    pub metric:      Option<i64>,
    #[serde(rename = "Scope")]
    pub scope:       Option<String>,
    #[serde(rename = "Src")]
    pub src:         Option<String>,
}

// PUT 整筆
#[derive(Debug, Deserialize)]
pub struct PutRouteRequest {
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Via")]
    pub via:         String,
    #[serde(rename = "Dev")]
    pub dev:         String,
    #[serde(rename = "Proto")]
    pub proto:       String,
    #[serde(rename = "Metric")]
    pub metric:      i64,
    #[serde(rename = "Scope")]
    pub scope:       String,
    #[serde(rename = "Src")]
    pub src:         String,
}
