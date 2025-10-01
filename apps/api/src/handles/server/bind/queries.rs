use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Queries {
    #[serde(rename = "Total")]
    pub total:    i64,
    #[serde(rename = "Success")]
    pub success:  i64,
    #[serde(rename = "NXDOMAIN")]
    pub nxdomain: i64,
    #[serde(rename = "REFUSED")]
    pub refused:  i64,
}
