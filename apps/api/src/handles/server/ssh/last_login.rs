use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub struct Last_Login {
    #[serde(rename = "User")]
    pub user: String,
    #[serde(rename = "Date")]
    pub date: Date,
    #[serde(rename = "Ip")]
    pub ip:   String,
}
