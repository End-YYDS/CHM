use serde::Serialize;

use crate::commons::Date;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
pub enum Query_Type {
    SELECT,
    INSERT,
    UPDATE,
    DELETE,
    CREATE,
    DROP,
    ALTER,
}

#[derive(Debug, Serialize)]
pub enum Status {
    Success,
    Error,
    Timeout,
}

#[derive(Debug, Serialize)]
pub struct Query_log {
    #[serde(rename = "Ip")]
    pub ip:            String,
    #[serde(rename = "Date")]
    pub date:          Date,
    #[serde(rename = "User")]
    pub user:          String,
    #[serde(rename = "Database")]
    pub database:      String,
    #[serde(rename = "Query")]
    pub query:         String,
    #[serde(rename = "Query_Type")]
    pub query_type:    Query_Type,
    #[serde(rename = "Duration_ms")]
    pub duration_ms:   i64,
    #[serde(rename = "Status")]
    pub status:        Status,
    #[serde(rename = "Affected_Rows")]
    pub affected_rows: i64,
}
