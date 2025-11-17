use serde::Serialize;

use crate::handles::server::squid::logs::acc_log::Access_log;

pub mod acc_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Access_Log")]
    pub access_log:        Vec<Access_log>,
    #[serde(rename = "Access_Log_Length")]
    pub access_log_length: usize,
}
