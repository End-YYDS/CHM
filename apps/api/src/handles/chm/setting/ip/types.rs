use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum Mode {
    #[serde(rename = "None")]
    None,
    #[serde(rename = "White")]
    White,
    #[serde(rename = "Black")]
    Black,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpEntry {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Ip")]
    pub ip:   String,
}

pub type IpMap = HashMap<String, IpEntry>;

#[derive(Debug, Serialize)]
pub struct GetIpResponse {
    #[serde(rename = "Mode")]
    pub mode:  Mode,
    #[serde(rename = "Lists")]
    pub lists: Option<IpMap>, // None 代表規格中的 "Lists": None
}

#[derive(Debug, Deserialize)]
pub struct PostIpRequest {
    #[serde(rename = "Mode")]
    pub mode: Mode,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Ip")]
    pub ip:   String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteIpRequest {
    #[serde(rename = "Mode")]
    pub mode: Mode,
    #[serde(rename = "Did")]
    pub did:  String, // 規格 did（資料庫 id），以 String 表示
}

#[derive(Debug, Deserialize)]
pub struct PutIpRequest {
    #[serde(rename = "Mode")]
    pub mode: Mode,
}
