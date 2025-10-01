use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum Status {
    active,
    inactive,
}

#[derive(Debug, Serialize)]
pub struct Shares {
    #[serde(rename = "Name")]
    pub name:        String,
    #[serde(rename = "Path")]
    pub path:        String,
    #[serde(rename = "Users")]
    pub users:       i64,
    #[serde(rename = "Permissions")]
    pub permissions: String,
    #[serde(rename = "Status")]
    pub status:      Status,
}

// "Shares": [
// {
// "Name": String, // 共享名稱
// "Path": String, // 共享的本地路徑
// "Users": Int, // 目前正在訪問該共享的使用者數量
// "Permissions": String, // 設定的存取權限（如 read, write）
// "Status": enum (active|inactive) // 該共享的狀態
// }
// ]
