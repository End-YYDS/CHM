use crate::{ApiResult, GlobalConfig};
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};
use uuid::Uuid;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "CHM_API";
static DEFAULT_PORT: u16 = 50050;
static DEFAULT_OTP_LEN: usize = 6;

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Services {
    #[serde(default = "Services::default_controller")]
    pub controller: String,
}

impl Services {
    fn default_controller() -> String {
        let controller_ip = if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        };
        "https://".to_string() + &controller_ip + ":50051"
    }
}
impl Default for Services {
    fn default() -> Self {
        Self { controller: Self::default_controller() }
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
    #[serde(default, rename = "CertInfo")]
    pub cert_info:   CertInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub bits:     u32,
    pub country:  String,
    pub state:    String,
    pub locality: String,
    pub org:      String,
    pub cn:       String,
    pub san:      Vec<String>,
    pub days:     u32,
}

impl Default for CertInfo {
    fn default() -> Self {
        Self {
            bits:     2048,
            country:  "TW".into(),
            state:    "Taiwan".into(),
            locality: "Taipei".into(),
            org:      "CHM-INIT".into(),
            cn:       ID.into(),
            san:      vec![],
            days:     1,
        }
    }
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
            cert_info:   CertInfo::default(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Settings {
    #[serde(default)]
    pub server:      Server,
    #[serde(default)]
    /// 憑證設定
    pub certificate: Certificate,
    #[serde(default)]
    pub services:    Services,
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
pub async fn config() -> ApiResult<()> {
    if NEED_EXAMPLE.load(Relaxed) {
        Settings::init(format!("{ID}_config.toml.example").as_str()).await?;
        return Ok(());
    }
    let settings = Settings::new()?;
    GlobalConfig::init(settings);
    Ok(())
}
