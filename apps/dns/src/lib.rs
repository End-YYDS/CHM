pub use crate::{
    config::{config, CertInfo},
    globals::GlobalConfig,
};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_project_const::uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicBool,
};
pub mod db;
pub mod error;
pub mod service;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMmDNS";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50053;
pub const DEFAULT_OTP_LEN: usize = 6;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;
pub const DEFAULT_TIMEOUT: u64 = 10;
pub const DEFAULT_BITS: i32 = 256;
pub const DEFAULT_CRL_UPDATE_INTERVAL: u64 = 3600; // 1 小時

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DnsExtension {
    #[serde(default)]
    pub db_info:    DnsDb,
    #[serde(default)]
    pub controller: Controller,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DnsDb {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub host:     String,
    #[serde(default)]
    pub port:     u16,
    #[serde(default)]
    pub dbname:   String,
}

impl Default for DnsDb {
    fn default() -> Self {
        Self {
            username: "chm".into(),
            password: "".into(),
            host:     IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
            port:     5432,
            dbname:   "dns".into(),
        }
    }
}

impl DnsDb {
    pub fn get_connection_string(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.dbname
        )
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
/// 控制器設定
pub struct Controller {
    /// 控制器的指紋，用於識別和驗證
    #[serde(default = "Controller::default_fingerprint")]
    pub fingerprint: String,
    /// 控制器的序列號，用於唯一標識
    #[serde(default = "Controller::default_serial")]
    pub serial:      String,
    /// 控制器的UUID
    #[serde(default = "Controller::default_uuid")]
    pub uuid:        Uuid,
}

impl Controller {
    /// 取得控制器的預設指紋
    pub fn default_fingerprint() -> String {
        "".into()
    }
    /// 取得控制器的預設序列號
    pub fn default_serial() -> String {
        "".into()
    }
    pub fn default_uuid() -> Uuid {
        Uuid::nil()
    }
}
declare_config!(extend = crate::DnsExtension);
declare_config_bus!();
