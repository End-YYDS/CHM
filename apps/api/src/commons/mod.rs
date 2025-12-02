use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

pub mod error_logs;
pub mod translate;

/// 帶 UUID 的請求結構體
#[derive(Debug, Serialize, Deserialize, ToSchema, IntoParams)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct UuidRequest {
    #[serde(rename = "Uuid", alias = "Uuid", alias = "uuid")]
    pub uuid: String,
}

/// 回應類型枚舉
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum ResponseType {
    Ok,
    Err,
    Unspecified,
}

/// 回應結果結構體
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct ResponseResult {
    pub r#type:  ResponseType,
    pub message: String,
}

/// 月份枚舉
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
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

/// 星期枚舉
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum Week {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// 時間結構體
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Time {
    pub hour: i64,
    pub min:  i64,
}

/// 日期结构体
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Date {
    pub year:  i64,
    pub month: Month,
    pub day:   i64,
    pub week:  Week,
    pub time:  Time,
}

/// 狀態枚舉
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub enum Status {
    Active,
    Stopped,
    Uninstalled,
}

/// 通用信息結構體
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct CommonInfo {
    pub hostname: String,
    pub status:   Status,
    pub cpu:      f64,
    pub memory:   f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip:       Option<String>,
}
