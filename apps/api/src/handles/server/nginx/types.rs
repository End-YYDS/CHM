use serde::Serialize;

use crate::{
    commons::CommonInfo,
    handles::server::nginx::{connections::Connections, logs::Logs},
};

#[derive(Debug, Serialize)]
pub struct NginxResponse {
    #[serde(flatten)]
    pub common_info: CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: Connections,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
