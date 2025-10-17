use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::commons::CommonInfo;

#[derive(Debug, Deserialize)]
pub struct stall_request {
    #[serde(rename = "Server")]
    pub server: String,
    #[serde(rename = "Uuids")]
    pub uuids:  Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct stalled_request {
    #[serde(rename = "Server")]
    pub server: String,
}

#[derive(Debug, Serialize)]
pub struct Pcs {
    #[serde(flatten)]
    pub uuids: HashMap<String, CommonInfo>,
}

#[derive(Debug, Serialize)]
pub struct stalledResponse {
    #[serde(rename = "Pcs")]
    pub pcs:    Pcs,
    #[serde(rename = "Length")]
    pub length: usize,
}
