use crate::commons::ResponseResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct PCManagerRequest {
    #[serde(rename = "Ip")]
    pub ip:       String,
    #[serde(rename = "Password")]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct Uuid {
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Ip")]
    pub ip:       String,
    #[serde(rename = "Status")]
    pub status:   bool,
}

// #[derive(Debug, Serialize)]
// pub struct Pcs {
//     pub uuid: Uuid,
// }

#[derive(Debug, Serialize)]
pub struct PcInformation {
    #[serde(rename = "Pcs")]
    pub pcs:    HashMap<String, Uuid>,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct SpecificRequest {
    #[serde(rename = "Uuid")]
    pub uuid: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeletePcRequest {
    #[serde(rename = "Uuids")]
    pub uuids:     Vec<String>,
    #[serde(rename = "Passwords")]
    pub passwords: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct DeletePcResponse {
    pub uuids: HashMap<String, ResponseResult>,
}

#[derive(Debug, Deserialize)]
pub struct UuidsRequest {
    #[serde(rename = "Uuids")]
    pub uuids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PostPcgroupRequest {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Describe")]
    pub describe:  String,
}

#[derive(Debug, Serialize)]
pub struct Vxlanid {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Pcs")]
    pub pcs:       Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Groups {
    #[serde(rename = "vxlanid")]
    pub vxlanid: Vxlanid,
}

#[derive(Debug, Serialize)]
pub struct GetPcgroupResponseResult {
    #[serde(rename = "Groups")]
    pub groups: Groups,
    #[serde(rename = "Length")]
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct DePutVxlanid {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Pcs")]
    pub pcs:       Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PutPcgroupRequest {
    pub vxlanid: DePutVxlanid,
}

#[derive(Debug, Deserialize)]
pub struct DePatchVxlanid {
    #[serde(rename = "Groupname")]
    pub groupname: String,
}

#[derive(Debug, Deserialize)]
pub struct PatchPcgroupRequest {
    pub vxlanid: DePatchVxlanid,
}

#[derive(Debug, Deserialize)]
pub struct DeletePcGroupRequest {
    #[serde(rename = "Vxlanid")]
    pub vxlanid: i64,
}
