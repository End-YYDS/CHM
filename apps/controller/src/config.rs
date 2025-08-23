use chm_config_loader::store_config;
use chm_dns_resolver::uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

use crate::{ConResult, GlobalConfig};

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "CHMcd";

#[derive(Debug, Deserialize, Serialize)]
pub struct Server {
    #[serde(default = "Server::default_host")]
    /// 伺服器主機名稱或 IP 地址
    pub host:       String,
    #[serde(default = "Server::default_port")]
    /// 伺服器埠號
    pub port:       u16,
    #[serde(default = "Server::default_otp_len")]
    /// 一次性密碼（OTP）的長度
    pub otp_len:    usize,
    #[serde(default = "Server::default_unique_id")]
    /// 伺服器的唯一識別碼
    pub unique_id:  Uuid,
    #[serde(default = "Server::default_dns_server")]
    /// DNS 伺服器地址
    pub dns_server: String,
    #[serde(default = "Server::default_ca_server")]
    /// mCA 伺服器地址
    pub ca_server:  String,
}

impl Server {
    /// 取得伺服器的完整地址
    fn default_host() -> String {
        if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        }
    }
    /// 取得伺服器的預設埠號
    fn default_port() -> u16 {
        50051
    }
    /// 一次性密碼的預設長度
    fn default_otp_len() -> usize {
        6
    }
    /// 伺服器的唯一識別碼
    fn default_unique_id() -> Uuid {
        Uuid::new_v4()
    }
    fn default_dns_server() -> String {
        let dnsip = if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        };
        "http://".to_string() + &dnsip + ":50053"
    }
    fn default_ca_server() -> String {
        let caip = if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        };
        "https://".to_string() + &caip + ":50052"
    }
}
impl Default for Server {
    fn default() -> Self {
        Server {
            host:       Server::default_host(),
            port:       Server::default_port(),
            otp_len:    Server::default_otp_len(),
            unique_id:  Server::default_unique_id(),
            dns_server: Server::default_dns_server(),
            ca_server:  Server::default_ca_server(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Certificate {
    #[serde(default = "Certificate::default_rootca")]
    /// 根憑證
    pub root_ca:     String,
    #[serde(default = "Certificate::default_client_cert")]
    /// 客戶端憑證
    pub client_cert: String,
    #[serde(default = "Certificate::default_client_key")]
    /// 客戶端私鑰
    pub client_key:  String,
    #[serde(default = "Certificate::default_passphrase")]
    /// 根憑證的密碼短語
    pub passphrase:  String,
}

impl Certificate {
    fn default_rootca() -> String {
        if cfg!(debug_assertions) {
            "certs/rootCA.pem".into()
        } else {
            "/etc/CHM/certs/rootCA.pem".into() // 預設在系統目錄下
        }
    }
    fn default_client_cert() -> String {
        if cfg!(debug_assertions) {
            "certs/controller.pem".to_string()
        } else {
            "/etc/CHM/certs/controller.pem".to_string() // 預設在系統目錄下
        }
    }
    fn default_client_key() -> String {
        if cfg!(debug_assertions) {
            "certs/controller.key".to_string()
        } else {
            "/etc/CHM/certs/controller.key".to_string() // 預設在系統目錄下
        }
    }
    fn default_passphrase() -> String {
        "".to_string()
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            root_ca:     Certificate::default_rootca(),
            client_cert: Certificate::default_client_cert(),
            client_key:  Certificate::default_client_key(),
            passphrase:  Certificate::default_passphrase(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Settings {
    #[serde(default)]
    /// 伺服器設定
    pub server:      Server,
    #[serde(default)]
    /// 憑證設定
    pub certificate: Certificate,
}

impl Settings {
    pub fn new() -> ConResult<Self> {
        Ok(chm_config_loader::load_config(ID, None, None)?)
    }
    pub async fn init(path: &str) -> ConResult<()> {
        store_config(&Settings::default(), path).await?;
        println!("Generated default config at {path}");
        Ok(())
    }
}

pub async fn config() -> ConResult<()> {
    if NEED_EXAMPLE.load(Relaxed) {
        Settings::init(format!("{ID}_config.toml.example").as_str()).await?;
        return Ok(());
    }
    let settings = Settings::new()?;
    GlobalConfig::init_global_config(settings).await;
    Ok(())
}
