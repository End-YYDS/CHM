use serde::{Deserialize, Serialize};

pub mod error_logs;
pub mod translate;

#[derive(Debug, Deserialize)]
pub struct UuidRequest {
    #[serde(rename = "Uuid", alias = "Uuid", alias = "uuid")]
    pub uuid: String,
}

#[derive(Debug, Serialize)]
pub enum ResponseType {
    #[serde(rename = "Ok")]
    Ok,
    #[serde(rename = "Err")]
    Err,
    #[serde(rename = "Unspecified")]
    Unspecified,
}

#[derive(Debug, Serialize)]
pub struct ResponseResult {
    #[serde(rename = "Type")]
    pub r#type:  ResponseType,
    #[serde(rename = "Message")]
    pub message: String,
}

#[derive(Debug, Serialize)]
pub enum Month {
    Jan,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
}

#[derive(Debug, Serialize)]
pub enum Week {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

#[derive(Debug, Serialize)]
pub struct Time {
    #[serde(rename = "Hour")]
    pub hour: i64,
    #[serde(rename = "Min")]
    pub min:  i64,
}

#[derive(Debug, Serialize)]
pub struct Date {
    #[serde(rename = "Year")]
    pub year:  i64,
    #[serde(rename = "Month")]
    pub month: Month,
    #[serde(rename = "Day")]
    pub day:   i64,
    #[serde(rename = "Week")]
    pub week:  Week,
    #[serde(rename = "Time")]
    pub time:  Time,
}

#[derive(Debug, Serialize)]
pub enum Status {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "uninstalled")]
    Uninstalled,
}

#[derive(Debug, Serialize)]
pub struct CommonInfo {
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Status")]
    pub status:   Status,
    #[serde(rename = "Cpu")]
    pub cpu:      f64,
    #[serde(rename = "Memory")]
    pub memory:   f64,
    #[serde(rename = "Ip", skip_serializing_if = "Option::is_none")]
    pub ip:       Option<String>,
}
