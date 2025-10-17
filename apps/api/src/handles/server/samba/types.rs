use serde::Serialize;

use crate::{
    commons::CommonInfo,
    handles::server::samba::{logs::Logs, shares::Shares},
};

#[derive(Debug, Serialize)]
pub struct SambaResponse {
    // Define the fields for the Samba response
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Shares")]
    pub shares:      Vec<Shares>,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
