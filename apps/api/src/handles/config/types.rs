use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct GetConfigQuery {
    #[serde(rename = "Name")]
    pub name: String, // 目前規格使用 "ReloadRate"
}

#[derive(Debug, Serialize)]
pub struct ReloadRateResponse {
    #[serde(rename = "ReloadRate")]
    pub reload_rate: i64,
}

/// 若要回傳整份設定（文件示意的 Config 區塊）
#[derive(Debug, Serialize, Default)]
pub struct Config {
    #[serde(rename = "ReloadRate")]
    pub reload_rate: i64,
    // 待增加...
}
