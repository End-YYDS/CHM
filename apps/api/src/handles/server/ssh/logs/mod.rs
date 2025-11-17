use serde::Serialize;

use crate::handles::server::ssh::logs::auth_log::Auth_Log;

pub mod auth_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Auth_log")]
    pub auth_log:        Vec<Auth_Log>,
    #[serde(rename = "Auth_log_length")]
    pub auth_log_length: usize,
}
