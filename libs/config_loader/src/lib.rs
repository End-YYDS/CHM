use std::path::PathBuf;

use config::{Config, Environment, File};
use directories::ProjectDirs;
use serde::de::DeserializeOwned;

pub const PROJECT: (&str, &str, &str) = ("com", "duacodie", "CHM");
pub struct ConfigLoader<T> {
    pub config: T,
    pub proj_dirs: ProjectDirs,
    pub config_file: Vec<PathBuf>,
}
impl<T> ConfigLoader<T> {
    pub fn new(config: T, proj_dirs: ProjectDirs, config_file: Vec<PathBuf>) -> Self {
        Self {
            config,
            proj_dirs,
            config_file,
        }
    }
}
pub fn load_config<T>(
    env_prefix: &str,
    system_config: Option<&str>,
    dev_config: Option<&str>,
) -> Result<(T, ProjectDirs), config::ConfigError>
where
    T: DeserializeOwned,
{
    //    Linux:   $XDG_CONFIG_HOME / $HOME/.config
    //    macOS:   ~/Library/Application Support
    //    Windows: {FOLDERID_RoamingAppData}
    let proj_dirs =
        ProjectDirs::from(PROJECT.0, PROJECT.1, PROJECT.2).expect("invalid project name");
    let default_system_path = PathBuf::from("/etc").join(PROJECT.2); //TODO: 安裝腳本安裝時注意資料夾權限問題
    let default_dev_path = PathBuf::from("config");
    let default_name = format!("{env_prefix}_config.toml");
    let system_config = system_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    // let user_config = user_config
    //     .filter(|s| !s.is_empty())
    //     .unwrap_or(&default_name);
    let dev_config = dev_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    let builder = Config::builder()
        // 系統級（不存在也沒關係）
        .add_source(File::from(default_system_path.join(system_config)).required(false))
        // 使用者級
        // .add_source(File::from(default_user_path.join(user_config)).required(false))
        // 本地範例（通常只有在開發或測試時才會存在）
        .add_source(File::from(default_dev_path.join(dev_config)).required(false))
        // 環境變數覆蓋：CHM_{$env_prefix}__PASSPHRASE
        .add_source(
            Environment::with_prefix(&format!("{}_{}", PROJECT.2, env_prefix))
                .prefix_separator("__")
                .separator("___"),
        );
    let ret = builder.build()?.try_deserialize::<T>();
    match ret {
        Ok(cfg) => Ok((cfg, proj_dirs)),
        Err(e) => Err(config::ConfigError::Message(format!(
            "Failed to deserialize config: {e}"
        ))),
    }
}

pub async fn store_config<T>(
    config: &T,
    is_debug: bool,
    file: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: serde::Serialize,
{
    let config_path = PathBuf::from("config").join(file);
    let save_path = if is_debug {
        config_path
    } else {
        PathBuf::from("/etc").join(PROJECT.2).join(config_path) //TODO: 安裝腳本安裝時注意資料夾權限問題
    };
    let s = toml::to_string_pretty(config)?;
    if let Some(parent) = save_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(save_path, s).await?;
    Ok(())
}
