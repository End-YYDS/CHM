use crate::ApiResult;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicBool,
};
use uuid::Uuid;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "CHM_API";
static DEFAULT_PORT: u16 = 50050;
static DEFAULT_OTP_LEN: usize = 6;

#[derive(Debug, Serialize, Deserialize)]
pub struct Server {
    #[serde(default = "Server::default_hostname")]
    pub hostname:  String,
    #[serde(default = "Server::default_host")]
    pub host:      String,
    #[serde(default = "Server::default_port")]
    pub port:      u16,
    #[serde(default = "Server::default_otp_len")]
    pub otp_len:   usize,
    #[serde(default = "Server::default_unique_id")]
    pub unique_id: Uuid,
}

impl Server {
    fn default_hostname() -> String {
        ID.into()
    }
    fn default_host() -> String {
        if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        }
    }
    fn default_port() -> u16 {
        DEFAULT_PORT
    }
    fn default_otp_len() -> usize {
        DEFAULT_OTP_LEN
    }
    fn default_unique_id() -> Uuid {
        Uuid::new_v4()
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            hostname:  Self::default_hostname(),
            host:      Self::default_host(),
            port:      Self::default_port(),
            otp_len:   Self::default_otp_len(),
            unique_id: Self::default_unique_id(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub server: Server,
}

impl Settings {
    pub fn new() -> ApiResult<Self> {
        Ok(chm_config_loader::load_config(ID, None, None)?)
    }
    pub async fn init(path: &str) -> ApiResult<()> {
        chm_config_loader::store_config(&Settings::default(), path).await?;
        println!("Generated default config at {path}");
        Ok(())
    }
}
