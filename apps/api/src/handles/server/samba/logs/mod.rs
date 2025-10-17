use serde::Serialize;

use crate::handles::server::samba::logs::samba_log::Samba_log;

pub mod samba_log;

#[derive(Debug, Serialize)]
pub struct Logs {
    #[serde(rename = "Samba_log")]
    pub samba_log:        Vec<Samba_log>,
    #[serde(rename = "Samba_log_Length")]
    pub samba_log_length: i64,
}

// "Logs": {
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
// "Samba_log_Length": Int // Samba 日誌的條目數
// }
