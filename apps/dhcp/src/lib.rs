pub mod db;
pub mod error;
pub mod service;
pub use crate::{
    config::{config, CertInfo},
    globals::GlobalConfig,
};
use chm_config_bus::{_reexports::Uuid, declare_config, declare_config_bus};
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::{path::PathBuf, sync::atomic::AtomicBool};

// 每個Service必須都要有的Constants
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHM_dhcpd";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50055;
pub const DEFAULT_OTP_LEN: usize = 6;
// ==================================
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;
pub const DEFAULT_TIMEOUT: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSettings {
    #[serde(default = "DbSettings::default_store_path")]
    pub store_path:      PathBuf,
    #[serde(default = "DbSettings::default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "DbSettings::default_timeout")]
    pub timeout:         u64,
}
impl DbSettings {
    fn default_store_path() -> PathBuf {
        ProjectConst::db_path().join("dhcp.db")
    }
    fn default_max_connections() -> u32 {
        DEFAULT_MAX_CONNECTIONS
    }
    fn default_timeout() -> u64 {
        DEFAULT_TIMEOUT
    }
}
impl Default for DbSettings {
    fn default() -> Self {
        Self {
            store_path:      Self::default_store_path(),
            max_connections: Self::default_max_connections(),
            timeout:         Self::default_timeout(),
        }
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DhcpExtension {
    #[serde(default)]
    pub db:         DbSettings,
    #[serde(default)]
    pub controller: Controller,
}
declare_config!(extend = crate::DhcpExtension);
declare_config_bus!();

#[derive(Debug, FromRow)]
pub struct LZone {
    pub id:          i64,
    pub name:        String,
    pub vni:         i64,
    pub network:     String,
    pub broadcast:   String,
    pub subnet_mask: String,
}

#[derive(Debug, FromRow)]
pub struct IpPool {
    pub id:      i64,
    pub zone_id: i64,
    pub ip:      String,
}
