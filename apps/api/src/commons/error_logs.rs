use crate::commons::Date;
use serde::Serialize;

#[allow(non_camel_case_types)]
#[allow(unused)]
#[derive(Debug, Serialize)]
pub enum Level {
    debug,
    info,
    notice,
    warn,
    error,
    crit,
    alert,
    emerg,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Serialize)]
pub struct Error_log {
    #[serde(rename = "Date")]
    pub date:    Date,
    #[serde(rename = "Module")]
    pub module:  String,
    #[serde(rename = "Level")]
    pub level:   Level,
    #[serde(rename = "Pid")]
    pub pid:     i64,
    #[serde(rename = "Client")]
    pub client:  String,
    #[serde(rename = "Message")]
    pub message: String,
}
