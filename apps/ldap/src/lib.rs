pub mod allocator;
pub mod error;
pub mod service;
mod srv_impl;

pub use crate::{
    config::{config, CertInfo},
    globals::GlobalConfig,
    srv_impl::add_user_impl,
};

use chm_config_bus::{declare_config, declare_config_bus};
use std::{path::PathBuf, sync::atomic::AtomicBool};

use chm_config_bus::_reexports::Uuid;
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};

// 每個Service必須都要有的Constants
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHM_ldapd";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50054;
pub const DEFAULT_OTP_LEN: usize = 6;
// ==================================

pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;
pub const DEFAULT_TIMEOUT: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsSettings {
    #[serde(default = "IdsSettings::default_store_path")]
    pub store_path:      PathBuf,
    #[serde(default = "IdsSettings::default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "IdsSettings::default_timeout")]
    pub timeout:         u64,
}
impl IdsSettings {
    fn default_store_path() -> PathBuf {
        ProjectConst::db_path().join("ids.db")
    }
    fn default_max_connections() -> u32 {
        DEFAULT_MAX_CONNECTIONS
    }
    fn default_timeout() -> u64 {
        DEFAULT_TIMEOUT
    }
}
impl Default for IdsSettings {
    fn default() -> Self {
        Self {
            store_path:      Self::default_store_path(),
            max_connections: Self::default_max_connections(),
            timeout:         Self::default_timeout(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatorSettings {
    #[serde(default = "AllocatorSettings::default_uid_start")]
    pub uid_start: i64,
    #[serde(default = "AllocatorSettings::default_gid_start")]
    pub gid_start: i64,
}
impl AllocatorSettings {
    fn default_uid_start() -> i64 {
        10000
    }
    fn default_gid_start() -> i64 {
        10000
    }
}
impl Default for AllocatorSettings {
    fn default() -> Self {
        Self { uid_start: Self::default_uid_start(), gid_start: Self::default_gid_start() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapSettings {
    #[serde(default = "LdapSettings::default_url")]
    pub url:           String,
    #[serde(default = "LdapSettings::default_base_dn")]
    pub base_dn:       String,
    #[serde(default = "LdapSettings::default_user_dn")]
    pub user_dn:       String,
    #[serde(default = "LdapSettings::default_group_dn")]
    pub group_dn:      String,
    #[serde(default = "LdapSettings::default_upg_dn")]
    pub upg_dn:        String,
    #[serde(default = "LdapSettings::default_web_dn")]
    pub web_dn:        String,
    #[serde(default = "LdapSettings::default_service_dn")]
    pub service_dn:    String,
    #[serde(default = "LdapSettings::default_bind_dn")]
    pub bind_dn:       String,
    #[serde(default = "LdapSettings::default_bind_password")]
    pub bind_password: String,
}
impl LdapSettings {
    fn default_url() -> String {
        #[cfg(debug_assertions)]
        {
            use std::net::Ipv4Addr;
            let addr = Ipv4Addr::LOCALHOST.to_string();
            format!("ldap://{addr}:389")
        }
        #[cfg(not(debug_assertions))]
        {
            use chm_dns_resolver::DnsResolver;
            use std::net::{IpAddr, Ipv4Addr};
            let addr =
                DnsResolver::get_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)).to_string();
            format!("ldap://{addr}:389")
        }
    }
    fn default_base_dn() -> String {
        "dc=chm,dc=com".to_string()
    }
    fn default_user_dn() -> String {
        "ou=Users,dc=chm,dc=com".to_string()
    }
    fn default_group_dn() -> String {
        "ou=Groups,dc=chm,dc=com".to_string()
    }
    fn default_upg_dn() -> String {
        "ou=UPG,ou=Groups,dc=chm,dc=com".to_string()
    }
    fn default_web_dn() -> String {
        "ou=WebRoles,dc=chm,dc=com".to_string()
    }
    fn default_service_dn() -> String {
        "ou=Service,dc=chm,dc=com".to_string()
    }
    fn default_bind_dn() -> String {
        "cn=admin,dc=chm,dc=com".to_string()
    }
    fn default_bind_password() -> String {
        "admin".to_string()
    }
}

impl Default for LdapSettings {
    fn default() -> Self {
        Self {
            url:           Self::default_url(),
            base_dn:       Self::default_base_dn(),
            user_dn:       Self::default_user_dn(),
            group_dn:      Self::default_group_dn(),
            upg_dn:        Self::default_upg_dn(),
            web_dn:        Self::default_web_dn(),
            service_dn:    Self::default_service_dn(),
            bind_dn:       Self::default_bind_dn(),
            bind_password: Self::default_bind_password(),
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LdapExtension {
    #[serde(default)]
    pub ids:           IdsSettings,
    #[serde(default)]
    pub allocator:     AllocatorSettings,
    #[serde(default)]
    pub ldap_settings: LdapSettings,
    #[serde(default)]
    pub controller:    Controller,
}
declare_config!(extend = crate::LdapExtension);
declare_config_bus!();
