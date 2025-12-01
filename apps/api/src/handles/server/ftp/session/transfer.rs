use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum TransferType {
    Upload,
    Download,
}

#[derive(Debug, Serialize)]
pub struct Transfer {
    #[serde(rename = "Type")]
    pub transfer_type: TransferType,
    #[serde(rename = "File")]
    pub file:          String,
    #[serde(rename = "Size")]
    pub size:          i64,
    #[serde(rename = "Speed")]
    pub speed:         i64,
}

// "Transfer": {
// "Type": enum (Upload|Download),
// "File": String, // 檔案名稱
// "Size": Int, // 檔案大小 (Bytes)
// "Speed": Int // 速度 (Bytes/s)
//   }
