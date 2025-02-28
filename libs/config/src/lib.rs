use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{io::Write, path::PathBuf};
const DEFAULT_CONFIG_PATH: &str = "/opt/CHM/config/config.json";
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
    #[serde(rename = "CHM_GRPC_SERVICE_IP")]
    grpc_service_ip: String,
    #[serde(rename = "CHM_REST_SERVICE_IP")]
    rest_service_ip: String,
    #[serde(rename = "DEBUG")]
    debug: bool,
}
impl Default for Config {
    fn default() -> Self {
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
            grpc_service_ip: "127.0.0.1:50051".to_string(),
            rest_service_ip: "127.0.0.1:8080".to_string(),
            debug: true,
        }
    }
}
impl Config {
    fn load() -> std::io::Result<Self> {
        let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
        if !config_path.exists() {
            let current_pwd = std::env::current_dir()
                .expect("Unable to get the current directory")
                .join("config.json");
            config_path = current_pwd;
        }
        let file = std::fs::File::open(config_path)?;
        let config_data: Config = serde_json::from_reader(file)?;
        Ok(config_data)
    }
    #[allow(unused)]
    fn create() {
        let config = Config::default();
        let json_config = serde_json::to_string_pretty(&config).unwrap();
        if let Some(parent) = PathBuf::from(DEFAULT_CONFIG_PATH).parent() {
            std::fs::create_dir_all(parent).expect("Unable to create a directory");
        }
        let mut file = std::fs::File::create(DEFAULT_CONFIG_PATH).expect("Unable to create a file");
        file.write_all(json_config.as_bytes())
            .expect("Unable to write to the file");
    }
}

pub struct ConfigManager {
    config: Config,
}

impl ConfigManager {
    pub fn new() -> std::io::Result<Self> {
        let config = Config::load()?;
        Ok(Self { config })
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
    pub fn get_grpc_service_ip(&self) -> &str {
        &self.config.grpc_service_ip
    }
    pub fn get_rest_service_ip(&self) -> &str {
        &self.config.rest_service_ip
    }
}

pub fn init_config_manager() -> std::io::Result<()> {
    let config_manager = ConfigManager::new()?;
    CONFIG_MANAGER
        .set(config_manager)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Failed to set config manager"))
}

pub fn get_config_manager() -> &'static ConfigManager {
    CONFIG_MANAGER
        .get()
        .expect("Config manager is not initialized")
}
