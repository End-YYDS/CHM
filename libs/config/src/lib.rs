use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write, path::PathBuf};
const DEFAULT_CONFIG_PATH: &str = "~/CHM/config/config.json";
static CONFIG_MANAGER: OnceCell<ConfigManager> = OnceCell::new();

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(rename = "TRUSTED_DOMAINS")]
    trusted_domains: Vec<String>,
    #[serde(rename = "ALLOWED_ORIGINS")]
    allowed_origins: Vec<String>,
    #[serde(rename = "ALLOWED_METHODS")]
    allowed_methods: Vec<String>,
    #[serde(rename = "ALLOWED_HEADERS")]
    allowed_headers: Vec<String>,
    #[serde(rename = "CORS_MAX_AGE")]
    cors_max_age: u64,
    #[serde(rename = "CHM_GRPC_SERVICE_IPS", default)]
    grpc_service_ips: HashMap<String, String>,
    #[serde(rename = "CHM_REST_SERVICE_IP")]
    rest_service_ip: String,
    #[serde(rename = "DEBUG")]
    debug: bool,
}
impl Default for Config {
    fn default() -> Self {
        let mut grpc_ips = HashMap::new();
        grpc_ips.insert("default".to_string(), "127.0.0.1:50050".to_string());
        grpc_ips.insert("controller".to_string(), "127.0.0.1:50051".to_string());
        grpc_ips.insert("ca".to_string(), "127.0.0.1:50052".to_string());
        grpc_ips.insert("agent1".to_string(), "127.0.0.1:50053".to_string());
        grpc_ips.insert("dns".to_string(), "127.0.0.1:50054".to_string());
        grpc_ips.insert("dhcp".to_string(), "127.0.0.1:50055".to_string());
        Self {
            trusted_domains: vec![
                "http://localhost:8080".to_string(),
                "http://127.0.0.1:8080".to_string(),
                "http://localhost:5173".to_string(),
            ],
            allowed_origins: vec![
                "http://localhost:8080".to_string(),
                "http://127.0.0.1:8080".to_string(),
                "http://localhost:5173".to_string(),
            ],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string()],
            allowed_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "X-Custom-Header".to_string(),
            ],
            cors_max_age: 3600,
            grpc_service_ips: grpc_ips,
            rest_service_ip: "127.0.0.1:8080".to_string(),
            debug: true,
        }
    }
}
impl Config {
    fn load() -> std::io::Result<Self> {
        let mut config_path = std::env::current_dir()
            .expect("Unable to get the current directory")
            .join("config.json");

        if !config_path.exists() {
            config_path = expand_tilde(DEFAULT_CONFIG_PATH);
        }
        let file = std::fs::File::open(config_path)?;
        let config_data: Config = serde_json::from_reader(file)?;
        Ok(config_data)
    }
    #[allow(unused)]
    fn create() {
        let config = Config::default();
        let json_config = serde_json::to_string_pretty(&config).unwrap();
        if let Some(parent) = expand_tilde(DEFAULT_CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent).expect("Unable to create a directory");
        }
        let mut file = std::fs::File::create(expand_tilde(DEFAULT_CONFIG_PATH))
            .expect("Unable to create a file");
        file.write_all(json_config.as_bytes())
            .expect("Unable to write to the file");
    }
}

#[derive(Debug)]
pub struct ConfigManager {
    config: Config,
}

impl ConfigManager {
    pub fn new() -> std::io::Result<Self> {
        let config = Config::load()?;
        Ok(Self { config })
    }
    pub fn new_with_init() -> std::io::Result<Self> {
        Config::create();
        Self::new()
    }
    pub fn is_debug(&self) -> bool {
        self.config.debug
    }
    pub fn get_trusted_domains(&self) -> &[String] {
        &self.config.trusted_domains
    }
    pub fn get_allowed_origins(&self) -> &[String] {
        &self.config.allowed_origins
    }
    pub fn get_allowed_methods(&self) -> &[String] {
        &self.config.allowed_methods
    }
    pub fn get_allowed_headers(&self) -> &[String] {
        &self.config.allowed_headers
    }
    pub fn get_cors_max_age(&self) -> u64 {
        self.config.cors_max_age
    }
    pub fn get_grpc_service_ip(&self, service_name: &str) -> &str {
        self.config
            .grpc_service_ips
            .get(service_name)
            .unwrap_or(&self.config.grpc_service_ips["default"])
    }
    pub fn get_rest_service_ip(&self) -> &str {
        &self.config.rest_service_ip
    }
}

fn init_config_manager(debug: Option<bool>) -> std::io::Result<()> {
    if CONFIG_MANAGER.get().is_some() {
        return Ok(());
    }
    let config_manager = match debug {
        Some(true) => ConfigManager::new_with_init()?,
        _ => ConfigManager::new()?,
    };
    CONFIG_MANAGER
        .set(config_manager)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to set config manager"))
}

pub fn get_config_manager(debug: bool) -> &'static ConfigManager {
    if CONFIG_MANAGER.get().is_none() {
        init_config_manager(Some(debug)).expect("Unable to initialize config manager1");
    }
    CONFIG_MANAGER
        .get()
        .expect("Config manager is not initialized")
}
pub fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~") {
        #[cfg(not(windows))]
        let home = std::env::var("HOME").expect("無法取得 HOME 環境變數");
        #[cfg(windows)]
        let home = env::var("USERPROFILE").expect("無法取得 USERPROFILE 環境變數");
        let rest = &path[2..];
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}
