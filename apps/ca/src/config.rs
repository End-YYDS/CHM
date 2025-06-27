use config_loader::store_config;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use crate::{globals::GlobalConfig, CaResult};

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub static ID: &str = "CA";
#[derive(Debug, Deserialize, Serialize)]
/// 伺服器設定
pub struct Server {
    #[serde(default = "Server::default_host")]
    /// 伺服器主機名稱或 IP 地址
    pub host: String,
    #[serde(default = "Server::default_port")]
    /// 伺服器埠號
    pub port: u16,
    #[serde(default = "Server::default_otp_len")]
    pub otp_len: usize,
}

impl Server {
    /// 取得伺服器的完整地址
    fn default_host() -> String {
        "127.0.0.1".into()
    }
    /// 取得伺服器的預設埠號
    fn default_port() -> u16 {
        50052
    }
    fn default_otp_len() -> usize {
        6
    }
}
impl Default for Server {
    fn default() -> Self {
        Server {
            host: Server::default_host(),
            port: Server::default_port(),
            otp_len: Server::default_otp_len(),
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum BackendConfig {
    /// SQLite 資料庫後端專屬設定
    /// 預設使用 `certs/cert_store.db` 作為資料庫檔案
    /// 最大連線數量預設為 5，逾時時間預設為 10 秒
    Sqlite {
        #[serde(default = "SqliteSettings::default_store_path")]
        store_path: String,
        #[serde(default = "SqliteSettings::default_max_connections")]
        max_connections: u32,
        #[serde(default = "SqliteSettings::default_timeout")]
        timeout: u64,
    },
}
impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Sqlite {
            store_path: SqliteSettings::default_store_path(),
            max_connections: SqliteSettings::default_max_connections(),
            timeout: SqliteSettings::default_timeout(),
        }
    }
}

struct SqliteSettings;
impl SqliteSettings {
    fn default_store_path() -> String {
        if cfg!(debug_assertions) {
            "certs/cert_store.db".into()
        } else {
            "/etc/CHM/db/cert_store.db".into()
        }
    }
    fn default_max_connections() -> u32 {
        5
    }
    fn default_timeout() -> u64 {
        10
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// 憑證設定
pub struct Certificate {
    #[serde(default = "Certificate::default_rootca")]
    /// 根憑證的路徑
    pub rootca: String,
    #[serde(default = "Certificate::default_rootca_key")]
    /// 根憑證的私鑰路徑
    pub rootca_key: String,
    #[serde(default = "Certificate::default_passphrase")]
    /// 根憑證的密碼短語
    pub passphrase: String,
    #[serde(default = "Certificate::default_bits")]
    pub bits: i32,
    #[serde(
        with = "humantime_serde",
        default = "Certificate::default_crl_update_interval"
    )]
    pub crl_update_interval: std::time::Duration,
    #[serde(flatten)]
    #[serde(default)]
    pub backend: BackendConfig,
}

impl Certificate {
    /// 生成憑證簽署請求（CSR）和私鑰
    fn default_rootca() -> String {
        if cfg!(debug_assertions) {
            "certs/rootCA.pem".into()
        } else {
            "/etc/CHM/certs/rootCA.pem".into() // 預設在系統目錄下
        }
    }
    /// 取得根憑證的私鑰路徑
    fn default_rootca_key() -> String {
        if cfg!(debug_assertions) {
            "certs/rootCA.key".into()
        } else {
            "/etc/CHM/certs/rootCA.key".into() // 預設在系統目錄下
        }
    }
    /// 取得預設的密碼短語
    fn default_passphrase() -> String {
        "".into()
    }
    fn default_bits() -> i32 {
        256
    }
    fn default_crl_update_interval() -> std::time::Duration {
        std::time::Duration::from_secs(3600) // 預設為 1 小時
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            rootca: Certificate::default_rootca(),
            rootca_key: Certificate::default_rootca_key(),
            passphrase: "".into(),
            backend: BackendConfig::default(),
            bits: Certificate::default_bits(),
            crl_update_interval: Certificate::default_crl_update_interval(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
/// 控制器設定
pub struct Controller {
    /// 控制器的指紋，用於識別和驗證
    #[serde(default = "Controller::default_fingerprint")]
    pub fingerprint: String,
    /// 控制器的序列號，用於唯一標識
    #[serde(default = "Controller::default_serial")]
    pub serial: String,
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
}

#[derive(Debug, Deserialize, Default, Serialize)]
/// 應用程式設定
pub struct Settings {
    #[serde(default)]
    /// 伺服器設定
    pub server: Server,
    #[serde(default)]
    /// 憑證設定
    pub certificate: Certificate,
    #[serde(default)]
    /// 控制器設定
    pub controller: Controller,
}

impl Settings {
    /// 建立新的設定實例，從系統和使用者的配置檔案讀取並支援環境變數覆蓋。
    /// # 參數
    /// * `proj_dirs` - 用於獲取使用者配置目錄的 `ProjectDirs` 實例
    /// # 回傳
    /// * `Result<Self, config::ConfigError>` - 返回設定實例或錯誤
    pub fn new() -> Result<(Self, ProjectDirs), Box<dyn std::error::Error>> {
        Ok(config_loader::load_config(ID, None, None)?)
    }
    /// 初始化設定檔，生成一個包含預設值的 TOML 檔案。
    /// # 參數
    /// * `path` - 要生成的設定檔路徑
    /// # 回傳
    /// * `Result<(), Box<dyn std::error::Error>>` - 返回結果，成功時為 Ok，失敗時為 Err
    pub async fn init(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        store_config(&Settings::default(), true, path).await?;
        println!("Generated default config at {path}");
        Ok(())
    }
}
/// 取得應用程式設定和專案目錄
/// # 回傳
/// * `Result<(), Box<dyn std::error::Error>>` 返回設定實例和專案目錄，或錯誤
pub async fn config() -> CaResult<()> {
    if NEED_EXAMPLE.load(Relaxed) {
        Settings::init("CA_config.toml.example").await?;
        return Ok(());
    }
    let settings = Settings::new()?;
    GlobalConfig::init_global_config(settings);
    Ok(())
}
