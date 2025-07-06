use chm_config_loader::store_config;
use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

use crate::{
    config::{Settings, ID},
    CaResult,
};

#[derive(Debug)]
pub struct GlobalConfig {
    pub settings: Settings,
}

static GLOBAL_CFG: OnceCell<RwLock<GlobalConfig>> = OnceCell::new();

impl GlobalConfig {
    pub fn init_global_config(cfg: Settings) {
        GLOBAL_CFG.get_or_init(|| RwLock::new(GlobalConfig { settings: cfg }));
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
        lock.try_write().is_err()
    }
    pub async fn save_config() -> CaResult<()> {
        if GlobalConfig::has_active_readers() {
            tracing::trace!("還有讀鎖沒有釋放!");
        }
        let cfg = &GlobalConfig::read().await.settings;
        let config_name = format!("{ID}_config.toml");
        store_config(cfg, &config_name).await?;
        Ok(())
    }
}
