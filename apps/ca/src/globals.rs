use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

use directories::ProjectDirs;

use crate::config::Settings;

#[derive(Debug)]
pub struct GlobalConfig {
    pub settings: Settings,
    pub dirs: ProjectDirs,
}

static GLOBAL_CFG: OnceCell<RwLock<GlobalConfig>> = OnceCell::new();

impl GlobalConfig {
    pub fn init_global_config(cfg: (Settings, ProjectDirs)) {
        GLOBAL_CFG.get_or_init(|| {
            RwLock::new(GlobalConfig {
                settings: cfg.0,
                dirs: cfg.1,
            })
        });
    }
    pub async fn read() -> tokio::sync::RwLockReadGuard<'static, GlobalConfig> {
        GLOBAL_CFG
            .get()
            .expect("Global configuration not initialized")
            .read()
            .await
    }

    pub async fn write() -> tokio::sync::RwLockWriteGuard<'static, GlobalConfig> {
        GLOBAL_CFG
            .get()
            .expect("Global configuration not initialized")
            .write()
            .await
    }
}
