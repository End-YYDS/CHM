use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};

use crate::commons::CommonInfo;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct stall_request {
    pub server: String,
    pub uuids:  Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct stalled_request {
    pub server: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum Pcs {
    Installed {
        #[serde(flatten)]
        uuids: HashMap<String, CommonInfo>,
    },
    NotInstalled {
        #[serde(flatten)]
        uuids: HashMap<String, String>,
    },
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct stalledResponse {
    pub pcs:    Pcs,
    pub length: usize,
}
