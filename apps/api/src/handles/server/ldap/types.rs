use serde::Serialize;

use crate::{commons::CommonInfo, handles::server::ldap::logs::Logs};

#[derive(Debug, Serialize)]
pub struct LDAPResponse {
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Entries")]
    pub entries:     i64,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
