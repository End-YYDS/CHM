use std::path::PathBuf;

use config::{Config, Environment, File};
use directories::ProjectDirs;
use serde::de::DeserializeOwned;

const PROJECT: (&str, &str, &str) = ("com", "example", "CHM");
pub fn load_config<T>(
    env_prefix: &str,
    system_config: Option<&str>,
    user_config: Option<&str>,
    dev_config: Option<&str>,
) -> Result<(T,ProjectDirs), config::ConfigError>
where
    T: DeserializeOwned,
{
    //    Linux:   $XDG_CONFIG_HOME / $HOME/.config
    //    macOS:   ~/Library/Application Support
    //    Windows: {FOLDERID_RoamingAppData}
    let proj_dirs =
        ProjectDirs::from(PROJECT.0, PROJECT.1, PROJECT.2).expect("invalid project name");
    let default_system_path = PathBuf::from("/etc").join(PROJECT.2);
    let default_user_path = proj_dirs.config_dir();
    let default_dev_path = PathBuf::from("config");
    let default_name = format!("{}_config.toml", env_prefix);
    let system_config = system_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    let user_config = user_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);
    let dev_config = dev_config
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_name);

    let builder = Config::builder()
        // 系統級（不存在也沒關係）
        .add_source(File::from(default_system_path.join(system_config)).required(false))
        // 使用者級
        .add_source(File::from(default_user_path.join(user_config)).required(false))
        // 本地範例（通常只有在開發或測試時才會存在）
        .add_source(File::from(default_dev_path.join(dev_config)).required(false))
        // 環境變數覆蓋：CHM_{$env_prefix}__PASSPHRASE
        .add_source(
            Environment::with_prefix(PROJECT.2)
                .prefix(env_prefix)
                .prefix_separator("_")
                .separator("__"),
        );
    let ret = builder.build()?.try_deserialize::<T>();
    match ret {
        Ok(cfg) => Ok((cfg, proj_dirs)),
        Err(e) => Err(config::ConfigError::Message(format!(
            "Failed to deserialize config: {}",
            e
        ))),
    }
}
