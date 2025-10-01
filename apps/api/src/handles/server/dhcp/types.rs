use serde::Serialize;

use crate::{commons::CommonInfo, handles::server::dhcp::logs::Logs};

#[derive(Debug, Serialize)]
pub struct DHCPResponse {
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Leases")]
    pub leases:      i64,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
