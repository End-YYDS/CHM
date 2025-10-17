use serde::Serialize;

use crate::{
    commons::CommonInfo,
    handles::server::bind::{logs::Logs, queries::Queries},
};

#[derive(Debug, Serialize)]
pub struct BindResponse {
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Queries")]
    pub queries:     Queries,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
