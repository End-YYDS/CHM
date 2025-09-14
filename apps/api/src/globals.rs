use crate::{
    config::{Settings, ID},
    ApiResult,
};
use tokio::sync::{OnceCell, RwLock};

static GLOBALS: OnceCell<RwLock<GlobalConfig>> = OnceCell::const_new();
#[derive(Debug)]
pub struct GlobalConfig {
    pub settings: Settings,
}

impl GlobalConfig {
    pub async fn init_global_config(cfg: Settings) {
        let initial = GlobalConfig { settings: cfg };
        GLOBALS.get_or_init(|| async { RwLock::new(initial) }).await;
    }
    pub async fn read() -> tokio::sync::RwLockReadGuard<'static, GlobalConfig> {
        GLOBALS.get().expect("Global configuration not initialized").read().await
    }
    pub async fn write() -> tokio::sync::RwLockWriteGuard<'static, GlobalConfig> {
        GLOBALS.get().expect("Global configuration not initialized").write().await
    }
    pub fn has_active_readers() -> bool {
        let lock = GLOBALS.get().expect("GlobalConfig not initialized");
        lock.try_write().is_err()
    }
    pub async fn save_config() -> ApiResult<()> {
        if GlobalConfig::has_active_readers() {
            tracing::trace!("還有讀鎖沒有釋放!");
        }
        let cfg = &GlobalConfig::read().await.settings;
        let config_name = format!("{ID}_config.toml");
        chm_config_loader::store_config(cfg, &config_name).await?;
        Ok(())
    }
}
