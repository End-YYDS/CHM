use config::{Config, Environment, File};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
const PROJECT_NAME: &str = "CHM";
#[derive(Debug, Deserialize, Serialize)]
pub struct Server {
    #[serde(default = "Server::default_host")]
    pub host: String,
    #[serde(default = "Server::default_port")]
    pub port: u16,
}

impl Server {
    fn default_host() -> String {
        "127.0.0.1".into()
    }
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
pub struct Certificate {
    #[serde(default = "Certificate::default_rootca")]
    pub rootca: String,
    #[serde(default = "Certificate::default_rootca_key")]
    pub rootca_key: String,
    #[serde(default = "Certificate::default_passphrase")]
    pub passphrase: String,
}

impl Certificate {
    fn default_rootca() -> String {
        "certs/rootCA.crt".into()
    }
    fn default_rootca_key() -> String {
        "certs/rootCA.key".into()
    }
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
pub struct Develop {
    pub debug: bool,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Controller {
    pub fingerprint: String,
}

#[derive(Debug, Deserialize, Default, Serialize)]
pub struct Settings {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub certificate: Certificate,
    #[serde(default)]
    pub develop: Develop,
    #[serde(default)]
    pub controller: Controller,
}

impl Settings {
    pub fn new(proj_dirs: &ProjectDirs) -> Result<Self, config::ConfigError> {
        //    Linux:   $XDG_CONFIG_HOME / $HOME/.config
        //    macOS:   ~/Library/Application Support
        //    Windows: {FOLDERID_RoamingAppData}
        let system_path = PathBuf::from(format!("/etc/{}/config.toml", PROJECT_NAME));
        let user_path = proj_dirs.config_dir().join("config.toml");
        let local_example = PathBuf::from("config/config.toml");
        let builder = Config::builder()
            // 系統級（不存在也沒關係）
            .add_source(File::from(system_path).required(false))
            // 使用者級
            .add_source(File::from(user_path).required(false))
            // 本地範例（通常只有在開發或測試時才會存在）
            .add_source(File::from(local_example).required(false))
            // 環境變數覆蓋：{{PROJECT_NAME}}__SERVER__PORT／{{PROJECT_NAME}}__DATABASE__URL
            .add_source(Environment::with_prefix(PROJECT_NAME).separator("__"));
        builder.build()?.try_deserialize()
    }
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

pub fn config(
    (qualifier, organization, application): (&str, &str, &str),
) -> Result<(Settings, ProjectDirs), Box<dyn std::error::Error>> {
    let proj_dirs =
        ProjectDirs::from(qualifier, organization, application).expect("invalid project name");
    if NEED_EXAMPLE.load(Relaxed) {
        let example = PathBuf::from("config/config.toml.example");
        Settings::init(&example)?;
    }
    let settings = Settings::new(&proj_dirs)?;
    Ok((settings, proj_dirs))
}
