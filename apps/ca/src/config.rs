use crate::{globals::GlobalConfig, CaResult};
use chm_config_loader::store_config;
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};
use uuid::Uuid;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "mCA";
static DEFAULT_PORT: u16 = 50052;
static DEFAULT_OTP_LEN: usize = 6;
static DEFAULT_MAX_CONNECTIONS: u32 = 5;
static DEFAULT_TIMEOUT: u64 = 10;
static DEFAULT_BITS: i32 = 256;
static DEFAULT_CRL_UPDATE_INTERVAL: u64 = 3600; // 1 小時
#[derive(Debug, Deserialize, Serialize, Clone)]
/// 伺服器設定
pub struct Server {
    #[serde(default = "Server::default_hostname")]
    pub hostname:  String,
    #[serde(default = "Server::default_host")]
    /// IP 地址
    pub host:      String,
    #[serde(default = "Server::default_port")]
    /// 伺服器埠號
    pub port:      u16,
    #[serde(default = "Server::default_otp_len")]
    /// 一次性密碼（OTP）的長度
    pub otp_len:   usize,
    #[serde(default = "Server::default_unique_id")]
    /// 伺服器的唯一識別碼
    pub unique_id: String,
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
    fn default_otp_len() -> usize {
        DEFAULT_OTP_LEN
    }
    fn default_unique_id() -> String {
        Uuid::new_v4().to_string()
    }
}
impl Default for Server {
    fn default() -> Self {
        Server {
            hostname:  Self::default_hostname(),
            host:      Self::default_host(),
            port:      Self::default_port(),
            otp_len:   Self::default_otp_len(),
            unique_id: Self::default_unique_id(),
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum BackendConfig {
    /// SQLite 資料庫後端專屬設定
    /// 預設使用 `certs/cert_store.db` 作為資料庫檔案
    /// 最大連線數量預設為 5，逾時時間預設為 10 秒
    Sqlite {
        #[serde(default = "SqliteSettings::default_store_path")]
        store_path:      String,
        #[serde(default = "SqliteSettings::default_max_connections")]
        max_connections: u32,
        #[serde(default = "SqliteSettings::default_timeout")]
        timeout:         u64,
    },
}
impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Sqlite {
            store_path:      SqliteSettings::default_store_path(),
            max_connections: SqliteSettings::default_max_connections(),
            timeout:         SqliteSettings::default_timeout(),
        }
    }
}

struct SqliteSettings;
impl SqliteSettings {
    fn default_store_path() -> String {
        ProjectConst::db_path().join("cert_store.db").display().to_string()
    }
    fn default_max_connections() -> u32 {
        DEFAULT_MAX_CONNECTIONS
    }
    fn default_timeout() -> u64 {
        DEFAULT_TIMEOUT
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// 憑證設定
pub struct Certificate {
    #[serde(default = "Certificate::default_rootca")]
    /// 根憑證的路徑
    pub rootca:              PathBuf,
    #[serde(default = "Certificate::default_rootca_key")]
    /// 根憑證的私鑰路徑
    pub rootca_key:          PathBuf,
    #[serde(default = "Certificate::default_passphrase")]
    /// 根憑證的密碼短語
    pub passphrase:          String,
    #[serde(default = "Certificate::default_bits")]
    pub bits:                i32,
    #[serde(with = "humantime_serde", default = "Certificate::default_crl_update_interval")]
    pub crl_update_interval: std::time::Duration,
    #[serde(flatten)]
    #[serde(default)]
    pub backend:             BackendConfig,
}

impl Certificate {
    /// 生成憑證簽署請求（CSR）和私鑰
    fn default_rootca() -> PathBuf {
        ProjectConst::certs_path().join("rootCA.pem")
    }
    /// 取得根憑證的私鑰路徑
    fn default_rootca_key() -> PathBuf {
        ProjectConst::certs_path().join("rootCA.key")
    }
    /// 取得預設的密碼短語
    fn default_passphrase() -> String {
        "".into()
    }
    fn default_bits() -> i32 {
        DEFAULT_BITS
    }
    fn default_crl_update_interval() -> std::time::Duration {
        std::time::Duration::from_secs(DEFAULT_CRL_UPDATE_INTERVAL)
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            rootca:              Certificate::default_rootca(),
            rootca_key:          Certificate::default_rootca_key(),
            passphrase:          "".into(),
            backend:             BackendConfig::default(),
            bits:                Certificate::default_bits(),
            crl_update_interval: Certificate::default_crl_update_interval(),
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

#[derive(Debug, Deserialize, Default, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
/// 應用程式設定
pub struct Settings {
    #[serde(default)]
    /// 伺服器設定
    pub server:      Server,
    #[serde(default)]
    /// 憑證設定
    pub certificate: Certificate,
    #[serde(default)]
    /// 控制器設定
    pub controller:  Controller,
}

impl Settings {
    /// 建立新的設定實例，從系統和使用者的配置檔案讀取並支援環境變數覆蓋。
    /// # 參數
    /// * `proj_dirs` - 用於獲取使用者配置目錄的 `ProjectDirs` 實例
    /// # 回傳
    /// * `Result<Self, config::ConfigError>` - 返回設定實例或錯誤
    pub fn new() -> CaResult<Self> {
        Ok(chm_config_loader::load_config(ID, None, None)?)
    }
    /// 初始化設定檔，生成一個包含預設值的 TOML 檔案。
    /// # 參數
    /// * `path` - 要生成的設定檔路徑
    /// # 回傳
    /// * `Result<(), Box<dyn std::error::Error>>` - 返回結果，成功時為
    ///   Ok，失敗時為 Err
    pub async fn init(path: &str) -> CaResult<()> {
        store_config(&Settings::default(), path).await?;
        println!("Generated default config at {path}");
        Ok(())
    }
}
/// 取得應用程式設定和專案目錄
/// # 回傳
/// * `Result<(), Box<dyn std::error::Error>>` 返回設定實例和專案目錄，或錯誤
pub async fn config() -> CaResult<()> {
    if NEED_EXAMPLE.load(Relaxed) {
        Settings::init(format!("{ID}_config.toml.example").as_str()).await?;
        return Ok(());
    }
    let settings = Settings::new()?;
    GlobalConfig::init(settings);
    Ok(())
}
