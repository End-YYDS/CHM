use serde::Serialize;

use crate::{commons::error_logs::Error_log, handles::server::dhcp::logs::lease_log::Lease_log};

pub mod lease_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Error_log")]
    pub error_log:  Vec<Error_log>,
    #[serde(rename = "Errlength")]
    pub errlength:  usize,
    #[serde(rename = "Lease_log")]
    pub lease_log:  Vec<Lease_log>,
    #[serde(rename = "Leaselength")]
    pub leaslength: usize,
}
