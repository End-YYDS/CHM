use serde::Serialize;

use crate::{
    commons::CommonInfo,
    handles::server::ftp::{logs::Logs, session::Sessions},
};

#[derive(Debug, Serialize)]
pub struct FTPResponse {
    // Define the fields for the FTP response
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Sessions")]
    pub sessions:    Sessions,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
