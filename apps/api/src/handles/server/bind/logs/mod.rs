use serde::Serialize;

use crate::{commons::error_logs::Error_log, handles::server::bind::logs::query_log::Query_log};
pub mod query_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Error_log")]
    pub error_log: Vec<Error_log>,
    #[serde(rename = "Errlength")]
    pub errlength: usize,
    #[serde(rename = "Query_log")]
    pub query_log: Vec<Query_log>,
    #[serde(rename = "Qrylength")]
    pub qrylength: usize,
}
