use crate::commons::Date;
use serde::Serialize;
use utoipa::ToSchema;

#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Access_log {
    pub ip:         String,
    pub date:       Date,
    pub method:     String,
    pub url:        String,
    pub protocol:   String,
    pub status:     i64,
    pub byte:       i64,
    pub referer:    String,
    pub user_agent: String,
}
