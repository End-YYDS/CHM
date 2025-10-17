use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub enum Level {
    info,
    warn,
    error,
}

#[derive(Debug, Serialize)]
pub struct Samba_log {
    #[serde(rename = "Date")]
    pub date:    Date,
    #[serde(rename = "Client")]
    pub client:  String, // 客戶端 IP 和端口
    #[serde(rename = "Event")]
    pub event:   String, // 事件描述（如共享訪問、認證失敗等）
    #[serde(rename = "Level")]
    pub level:   Level, // 記錄等級
    #[serde(rename = "Message")]
    pub message: String, // 具體訊息
}

// "Samba_log": [
// {
// "Date": {
// "Year": Int,
// "Month": enum (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec),
// "Day": Int,
// "Time": {
// "Hour": Int,
// "Min": Int
// }
// },
// "Client": String, // 客戶端 IP 和端口
// "Event": String, // 事件描述（如共享訪問、認證失敗等）
// "Level": enum (info|warn|error), // 記錄等級
// "Message": String // 具體訊息
// } // ...
// ],
