use serde::Serialize;

use crate::handles::server::ftp::session::{login_time::Login_Time, transfer::Transfer};

pub mod login_time;
pub mod transfer;

#[derive(Debug, Serialize)]
pub enum Status {
    Idle,
    Uploading,
    Downloading,
    Disconnected,
}

#[derive(Debug, Serialize)]
pub struct Sessions {
    #[serde(rename = "Ip")]
    pub ip:          String,
    #[serde(rename = "Username")]
    pub username:    String,
    #[serde(rename = "Login_Time")]
    pub login_time:  Login_Time,
    #[serde(rename = "Current_Dir")]
    pub current_dir: String,
    #[serde(rename = "Status")]
    pub status:      Status,
    #[serde(rename = "Transfer")]
    pub transfer:    Transfer,
}

// "Status": enum (Idle|Uploading|Downloading|Disconnected)
