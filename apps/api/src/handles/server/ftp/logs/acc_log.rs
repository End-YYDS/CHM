use serde::Serialize;

use crate::commons::Date;

#[derive(Debug, Serialize)]
pub enum Action {
    Login,
    Logout,
    Upload,
    Download,
    Delete,
    Rename,
}

#[derive(Debug, Serialize)]
pub enum Status {
    Success,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct Access_log {
    #[serde(rename = "Ip")]
    pub ip:       String,
    #[serde(rename = "Date")]
    pub date:     Date,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Action")]
    pub action:   Action,
    #[serde(rename = "File")]
    pub file:     String,
    #[serde(rename = "Size")]
    pub size:     i64,
    #[serde(rename = "Status")]
    pub status:   Status,
}

//  "Access_log": [
// {
// "Ip": String,
// "Date": {
// "Year": Int,
// "Month": enum (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec),
// "Day": Int,
// "Time": {
// "Hour": Int,
// "Min": Int
// }
// },
// "Username": String, // 登入使用者
// "Action": enum (Login|Logout|Upload|Download|Delete|Rename), // FTP 行為
// "File": String, // 操作的檔案名稱（若適用）
// "Size": Int, // 檔案大小（若適用，Bytes）
// "Status": enum (Success|Failed) // 操作結果
// } // ...
// ],
