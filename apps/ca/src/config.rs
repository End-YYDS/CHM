use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
#[derive(Debug, Deserialize, Serialize)]
/// 伺服器設定
pub struct Server {
    #[serde(default = "Server::default_host")]
    /// 伺服器主機名稱或 IP 地址
    pub host: String,
    #[serde(default = "Server::default_port")]
    /// 伺服器埠號
    pub port: u16,
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
}
impl Default for Server {
    fn default() -> Self {
        Server {
            host: Server::default_host(),
            port: Server::default_port(),
        }
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
}

impl Certificate {
    /// 生成憑證簽署請求（CSR）和私鑰
    fn default_rootca() -> String {
        "certs/rootCA.crt".into()
    }
    /// 取得根憑證的私鑰路徑
    fn default_rootca_key() -> String {
        "certs/rootCA.key".into()
    }
    /// 取得預設的密碼短語
    fn default_passphrase() -> String {
        "".into()
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            rootca: Certificate::default_rootca(),
            rootca_key: Certificate::default_rootca_key(),
            passphrase: "".into(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
/// 開發模式設定
pub struct Develop {
    /// 是否啟用開發模式
    pub debug: bool,
}

#[derive(Debug, Deserialize, Serialize, Default)]
/// 控制器設定
pub struct Controller {
    /// 控制器的指紋，用於識別和驗證
    pub fingerprint: String,
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
    /// 開發模式設定
    pub develop: Develop,
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
    pub fn new() -> Result<(Self,ProjectDirs), config::ConfigError> {
       config_loader::load_config("CA", None, None, None)
    }
    /// 初始化設定檔，生成一個包含預設值的 TOML 檔案。
    /// # 參數
    /// * `path` - 要生成的設定檔路徑
    /// # 回傳
    /// * `Result<(), Box<dyn std::error::Error>>` - 返回結果，成功時為 Ok，失敗時為 Err
    pub fn init(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let cfg = Settings::default();
        let s = toml::to_string_pretty(&cfg)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, s)?;
        println!("Generated default config at {}", path.display());
        Ok(())
    }
}
/// 取得應用程式設定和專案目錄
/// # 參數
/// * `qualifier` - 應用程式的限定符，例如 "com.example"
/// * `organization` - 應用程式的組織名稱，例如 "ExampleOrg"
/// * `application` - 應用程式名稱，例如 "MyApp"
/// # 回傳
/// * `Result<(Settings, ProjectDirs), Box<dyn std::error::Error>>` 返回設定實例和專案目錄，或錯誤
pub fn config(
) -> Result<(Settings, ProjectDirs), Box<dyn std::error::Error>> {
    if NEED_EXAMPLE.load(Relaxed) {
        let example = PathBuf::from("config/config.toml.example");
        Settings::init(&example)?;
    }
    let settings = Settings::new()?;
    Ok(settings)
}
