use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Connections {
    #[serde(rename = "Active")]
    pub active:   i64,
    #[serde(rename = "Accepted")]
    pub accepted: i64,
    #[serde(rename = "Handled")]
    pub handled:  i64,
    #[serde(rename = "Requests")]
    pub requests: i64,
}
