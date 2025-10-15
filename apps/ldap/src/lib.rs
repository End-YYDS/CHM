pub mod allocator;
pub mod error;
pub mod service;
mod srv_impl;

pub use crate::{config::config, globals::GlobalConfig};

use chm_config_bus::{declare_config, declare_config_bus};
use std::{path::PathBuf, sync::atomic::AtomicBool};

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
            let addr = DnsResolver::get_local_ip().unwrap_or(Ipv4Addr::LOCALHOST).to_string();
            format!("ldap://{addr}:389")
        }
    }
    fn default_base_dn() -> String {
        "dc=chm,dc=com".to_string()
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
            bind_dn:       Self::default_bind_dn(),
            bind_password: Self::default_bind_password(),
        }
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
}
declare_config!(extend = crate::LdapExtension);
declare_config_bus!();
