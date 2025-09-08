use serde::Serialize;

use crate::{
    commons::CommonInfo,
    handles::server::ssh::{last_login::Last_Login, logs::Logs},
};

#[derive(Debug, Serialize)]
pub struct SSHResponse {
    #[serde(flatten)]
    pub common:      CommonInfo,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Last_Login")]
    pub last_login:  Last_Login,
    #[serde(rename = "Logs")]
    pub logs:        Logs,
}
