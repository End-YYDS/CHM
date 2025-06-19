use config_loader::store_config;
use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

use directories::ProjectDirs;

use crate::{
    config::{is_debug, Settings, ID},
    CaResult,
};

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
    pub fn has_active_readers() -> bool {
        let lock = GLOBAL_CFG.get().expect("GlobalConfig not initialized");

        // tokio::sync::RwLock::try_write() 返回 Option<WriteGuard>
        // 如果返回 None，说明已有读锁或写锁存在
        lock.try_write().is_err()
    }
    pub async fn save_config() -> CaResult<()> {
        if GlobalConfig::has_active_readers() {
            eprintln!("⚠️ 还有读锁没释放！1");
        }
        let cfg = &GlobalConfig::read().await.settings;
        let config_name = format!("{}_config.toml", ID);
        store_config(cfg, is_debug(), &config_name).await?;
        Ok(())
    }
}
