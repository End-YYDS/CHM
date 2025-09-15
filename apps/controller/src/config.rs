use crate::{ConResult, GlobalConfig};
use chm_config_loader::store_config;
use chm_dns_resolver::uuid::Uuid;
use chm_project_const::ProjectConst;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "CHMcd";
static DEFAULT_PORT: u16 = 50051;
static DEFAULT_OTP_LEN: usize = 6;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Server {
    #[serde(default = "Server::default_hostname")]
    pub hostname:   String,
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
    fn default_hostname() -> String {
        ID.into()
    }
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
        DEFAULT_PORT
    }
    /// 一次性密碼的預設長度
    fn default_otp_len() -> usize {
        DEFAULT_OTP_LEN
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
            hostname:   Self::default_hostname(),
            host:       Self::default_host(),
            port:       Self::default_port(),
            otp_len:    Self::default_otp_len(),
            unique_id:  Self::default_unique_id(),
            dns_server: Self::default_dns_server(),
            ca_server:  Self::default_ca_server(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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
        ProjectConst::certs_path().join("rootCA.pem").display().to_string()
    }
    fn default_client_cert() -> String {
        ProjectConst::certs_path().join(format!("{ID}.pem")).display().to_string()
    }
    fn default_client_key() -> String {
        ProjectConst::certs_path().join(format!("{ID}.key")).display().to_string()
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

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[serde(flatten)]
    pub services_uuid: DashMap<String, Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Settings {
    #[serde(default)]
    /// 伺服器設定
    pub server:        Server,
    #[serde(default)]
    /// 憑證設定
    pub certificate:   Certificate,
    #[serde(default)]
    pub services_pool: ServicesPool,
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
    GlobalConfig::init(settings);
    Ok(())
}
