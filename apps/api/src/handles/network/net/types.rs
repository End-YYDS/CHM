use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub enum NicType {
    Virtual,
    Physical,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub enum NicStatus {
    Up,
    Down,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkItem {
    // #[serde(rename = "Name")] // 規格目前註解掉
    // pub name: String,
    pub nic_type:  NicType,
    pub ipv4:      String,
    pub netmask:   String,
    pub mac:       String,
    pub broadcast: String,
    pub mtu:       i64,
    pub status:    NicStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PcNetworks {
    pub networks: HashMap<String, NetworkItem>, // nid -> item
    pub length:   usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetAllNetResponse {
    pub pcs:    HashMap<String, PcNetworks>, // uuid -> networks
    pub length: usize,
}

// POST /api/network/net
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateNetRequest {
    pub nid:       String,
    #[serde(rename = "Type")]
    pub nic_type:  NicType,
    pub ipv4:      String,
    pub netmask:   String,
    pub mac:       String,
    pub broadcast: String,
    pub mtu:       i64,
    pub status:    NicStatus,
}

// DELETE /api/network/net
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteNetRequest {
    pub nid: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PatchOp {
    Ipv4 {
        #[serde(rename = "Ipv4")]
        ipv4: String,
    },
    Netmask {
        #[serde(rename = "Netmask")]
        netmask: String,
    },
    Mac {
        #[serde(rename = "Mac")]
        mac: String,
    },
    Broadcast {
        #[serde(rename = "Broadcast")]
        broadcast: String,
    },
    Mtu {
        #[serde(rename = "Mtu")]
        mtu: i64,
    },
    Status {
        #[serde(rename = "Status")]
        status: NicStatus,
    },
    TypeValue {
        #[serde(rename = "Type")]
        r#type: NicType,
    },
}

// PATCH /api/network/net —— 單一項目
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PatchNetRequest {
    pub nid: String,
    #[serde(flatten)]
    pub op:  PatchOp,
}

// PUT /api/network/net —— 整筆更新
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PutNetRequest {
    pub nid:       String,
    pub r#type:    NicType,
    pub ipv4:      String,
    pub netmask:   String,
    pub mac:       String,
    pub broadcast: String,
    pub mtu:       i64,
    pub status:    NicStatus,
}

// action up/down
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionNetRequest {
    pub nid: String,
}
