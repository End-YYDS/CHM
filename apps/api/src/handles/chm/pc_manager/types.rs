use crate::commons::ResponseResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PCManagerRequest {
    pub ip:       String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Uuid {
    pub hostname: String,
    pub ip:       String,
    pub status:   bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PcInformation {
    pub pcs:    HashMap<String, Uuid>,
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema, IntoParams)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct SpecificRequest {
    pub uuid: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeletePcRequest {
    pub uuids:     Vec<String>,
    pub passwords: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeletePcResponse {
    pub pcs:    HashMap<String, ResponseResult>,
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct UuidsRequest {
    pub uuids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PostPcgroupRequest {
    #[serde(rename = "Groupname")]
    pub groupname: String,
    #[serde(rename = "Cidr")]
    pub cidr:      String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Vxlanid {
    pub groupname: String,
    pub pcs:       Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct GetPcgroupResponseResult {
    pub groups: HashMap<String, Vxlanid>,
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DePutVxlanid {
    pub groupname: String,
    pub pcs:       Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PutPcgroupRequest {
    #[serde(flatten)]
    pub data: HashMap<String, DePutVxlanid>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase", untagged)]
pub enum DePatchVxlanid {
    Groupname { groupname: String },
    Pcs { pcs: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct PatchPcgroupRequest {
    #[serde(flatten)]
    pub data: HashMap<String, DePatchVxlanid>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct DeletePcGroupRequest {
    pub vxlanid: i64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct RebootPcResponse {
    pub pcs:    HashMap<String, ResponseResult>,
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ShutdownPcResponse {
    pub pcs:    HashMap<String, ResponseResult>,
    pub length: usize,
}
