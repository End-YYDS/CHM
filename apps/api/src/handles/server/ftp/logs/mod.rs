use serde::Serialize;

use crate::{commons::error_logs::Error_log, handles::server::ftp::logs::acc_log::Access_log};

pub mod acc_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Error_log")]
    pub error_log:  Vec<Error_log>,
    #[serde(rename = "Errlength")]
    pub errlength:  usize,
    #[serde(rename = "Access_log")]
    pub access_log: Vec<Access_log>,
    #[serde(rename = "Acclength")]
    pub acclength:  usize,
}
