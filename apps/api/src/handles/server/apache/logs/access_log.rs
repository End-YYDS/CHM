use crate::commons::Date;
use serde::Serialize;

#[allow(non_camel_case_types)]
#[derive(Debug, Serialize)]
pub struct Access_log {
    #[serde(rename = "Ip")]
    pub ip:         String,
    #[serde(rename = "Date")]
    pub date:       Date,
    #[serde(rename = "Method")]
    pub method:     String,
    #[serde(rename = "URL")]
    pub url:        String,
    #[serde(rename = "Protocol")]
    pub protocol:   String,
    #[serde(rename = "Status")]
    pub status:     i64,
    #[serde(rename = "Byte")]
    pub byte:       i64,
    #[serde(rename = "Referer")]
    pub referer:    String,
    #[serde(rename = "User_Agent")]
    pub user_agent: String,
}
