use serde::Serialize;

use crate::commons::Date;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
pub enum Method {
    BIND,
    SEARCH,
    ADD,
    DELETE,
    MODIFY,
    MODDN,
    COMPARE,
    UNBIND,
    EXTENDED,
}

#[derive(Debug, Serialize)]
pub enum Protocol {
    LDAPv2,
    LDAPv3,
}

#[derive(Debug, Serialize)]
pub enum Status {
    Success,
    AuthFailed,
    NotFound,
    Error,
}

#[derive(Debug, Serialize)]
pub struct Access_log {
    #[serde(rename = "Ip")]
    pub ip:               String,
    #[serde(rename = "Date")]
    pub date:             Date,
    #[serde(rename = "Method")]
    pub method:           Method,
    #[serde(rename = "Base_DN")]
    pub base_dn:          String,
    #[serde(rename = "Filter")]
    pub filter:           String,
    #[serde(rename = "Protocol")]
    pub protocol:         Protocol,
    #[serde(rename = "Status")]
    pub status:           Status,
    #[serde(rename = "Response_Time_ms")]
    pub response_time_ms: i64,
}
