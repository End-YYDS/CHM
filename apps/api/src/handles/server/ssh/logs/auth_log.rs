use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub enum Action {
    login,
    logout,
    failed_login,
}

#[derive(Debug, Serialize)]
pub enum Result {
    success,
    failure,
}

#[derive(Debug, Serialize)]
pub struct Auth_Log {
    #[serde(rename = "Date")]
    pub date:    Date,
    #[serde(rename = "User")]
    pub user:    String,
    #[serde(rename = "Action")]
    pub action:  Action,
    #[serde(rename = "Result")]
    pub result:  Result,
    #[serde(rename = "Ip")]
    pub ip:      String,
    #[serde(rename = "Message")]
    pub message: String,
}
