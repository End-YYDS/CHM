use std::path::PathBuf;

use config::{Config, Environment, File};
use project_const::ProjectConst;
use serde::de::DeserializeOwned;
pub extern crate toml;
pub struct ConfigLoader<T> {
    pub config: T,
    pub config_file: Vec<PathBuf>,
}
impl<T> ConfigLoader<T> {
    pub fn new(config: T, config_file: Vec<PathBuf>) -> Self {
        Self {
            config,
            config_file,
        }
    }
}
pub fn load_config<T>(
    env_prefix: &str,
    system_config: Option<&str>,
    dev_config: Option<&str>,
) -> Result<T, config::ConfigError>
where
    T: DeserializeOwned,
{
    let default_system_path = ProjectConst::release_save_dir(); //TODO: 安裝腳本安裝時注意資料夾權限問題
    let default_dev_path = PathBuf::from("config");
    let default_name = format!("{env_prefix}_config.toml");
    let system_config = system_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    let dev_config = dev_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    let builder = Config::builder()
        .add_source(File::from(default_system_path.join(system_config)).required(false))
        .add_source(File::from(default_dev_path.join(dev_config)).required(false))
        // 環境變數覆蓋：CHM_{$env_prefix}__PASSPHRASE
        .add_source(
            Environment::with_prefix(&format!("{}_{}", ProjectConst::PROJECT_NAME, env_prefix))
                .prefix_separator("__")
                .separator("___"),
        );
    let ret = builder.build()?.try_deserialize::<T>();
    match ret {
        Ok(cfg) => Ok(cfg),
        Err(e) => Err(config::ConfigError::Message(format!(
            "Failed to deserialize config: {e}"
        ))),
    }
}

pub async fn store_config<T>(config: &T, file: &str) -> Result<(), Box<dyn std::error::Error>>
where
    T: serde::Serialize,
{
    let config_path = ProjectConst::config_path().join(file);
    let s = toml::to_string_pretty(config)?;
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(config_path, s).await?;
    Ok(())
}
