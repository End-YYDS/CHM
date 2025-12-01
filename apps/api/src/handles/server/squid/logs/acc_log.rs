use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub struct Access_log {
    #[serde(rename = "Ip")]
    pub ip:           String,
    #[serde(rename = "Date")]
    pub date:         Date,
    #[serde(rename = "Method")]
    pub method:       String,
    #[serde(rename = "URL")]
    pub url:          String,
    #[serde(rename = "Status")]
    pub status:       i64,
    #[serde(rename = "Bytes_Served")]
    pub bytes_served: i64,
    #[serde(rename = "Referer")]
    pub referer:      String,
    #[serde(rename = "User_Agent")]
    pub user_agent:   String,
}

// "Method": String, // 請求方法（如 GET, POST）
// "URL": String, // 請求的 URL
// "Status": Int, // HTTP 狀態碼（如 200 成功，404 找不到）
// "Bytes_Served": Int, // 回應的位元組數
// "Referer": String, // 來源網站（如 "https://example.com"）
// "User_Agent": String // 使用者瀏覽器資訊
