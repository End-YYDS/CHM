use std::path::{Path, PathBuf};

use chm_project_const::ProjectConst;
use config::{Config, Environment, File};
use serde::de::DeserializeOwned;
use tokio::fs;

pub extern crate toml;
pub struct ConfigLoader<T> {
    pub config: T,
    pub config_file: Vec<PathBuf>,
}
impl<T> ConfigLoader<T> {
    pub fn new(config: T, config_file: Vec<PathBuf>) -> Self {
        Self { config, config_file }
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
    let system_dir = ProjectConst::config_path();
    let dev_dir = PathBuf::from("config");
    let default_name = format!("{env_prefix}_config.toml");
    let system_name = system_config.filter(|s| !s.is_empty()).unwrap_or(&default_name);
    let dev_name = dev_config.filter(|s| !s.is_empty()).unwrap_or(&default_name);
    let sys_path = system_dir.join(system_name);
    let dev_path = dev_dir.join(dev_name);

    let builder = Config::builder()
        .add_source(File::from(sys_path).required(false))
        .add_source(File::from(dev_path).required(false))
        // 環境變數覆蓋：CHM_{$env_prefix}__PASSPHRASE
        .add_source(
            Environment::with_prefix(&format!("{}_{}", ProjectConst::PROJECT_NAME, env_prefix))
                .prefix_separator("__")
                .separator("___"),
        );
    let ret = builder.build()?.try_deserialize::<T>();
    match ret {
        Ok(cfg) => Ok(cfg),
        Err(e) => Err(config::ConfigError::Message(format!("Failed to deserialize config: {e}"))),
    }
}

pub async fn store_config<T>(
    config: &T,
    file: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: serde::Serialize,
{
    let config_path = ProjectConst::config_path().join(file);
    let s = toml::to_string_pretty(config)?;
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    atomic_write(&config_path, s.as_bytes()).await?;
    Ok(())
}

async fn atomic_write(
    path: &Path,
    content: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content).await?;
    fs::rename(&tmp_path, path).await?;
    Ok(())
}
