use crate::commons::Date;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// 日志等级
#[allow(non_camel_case_types)]
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
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

/// 錯誤日志结构体
#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
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
