use crate::{
    commons::error_logs::Error_log, handles::server::apache::logs::access_log::Access_log,
};
use serde::Serialize;
use utoipa::ToSchema;

pub mod access_log;

#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Logs {
    pub error_log:  Vec<Error_log>,
    pub errlength:  usize,
    pub access_log: Vec<Access_log>,
    pub acclength:  usize,
}
