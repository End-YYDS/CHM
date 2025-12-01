use serde::Serialize;

use crate::{commons::error_logs::Error_log, handles::server::mysql::logs::query_log::Query_log};

pub mod query_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Error_log")]
    pub log_count:   Vec<Error_log>,
    #[serde(rename = "Errlength")]
    pub errlength:   usize,
    #[serde(rename = "Query_log")]
    pub query_log:   Vec<Query_log>,
    #[serde(rename = "Querylength")]
    pub querylength: usize,
}
