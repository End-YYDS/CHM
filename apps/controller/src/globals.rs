use crate::ID;
use chm_project_const::ProjectConst;
use tokio::sync::{OnceCell, RwLock};

use crate::config::Settings;
#[derive(Debug)]
pub struct GlobalConfig {
    pub settings: Settings,
}

static GLOBALS: OnceCell<RwLock<GlobalConfig>> = OnceCell::const_new();

pub const DEFAULT_CA: &str = "https://mCA.chm.com:50052";
pub const DEFAULT_DNS: &str = "http://127.0.0.1:50053";
pub async fn certificate_loader() -> (String, String, String) {
    let cert_path = ProjectConst::certs_path();
    (
        cert_path.join("rootCA.pem").display().to_string(),
        cert_path.join("controller.pem").display().to_string(),
        cert_path.join("controller.key").display().to_string(),
    )
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
    pub async fn save_config() -> crate::ConResult<()> {
        if GlobalConfig::has_active_readers() {
            tracing::trace!("還有讀鎖沒有釋放!");
        }
        let cfg = &GlobalConfig::read().await.settings;
        let config_name = format!("{ID}_config.toml");
        chm_config_loader::store_config(cfg, &config_name).await?;
        Ok(())
    }
}

pub async fn reload_globals(mca_ip: Option<String>, mdns_info: Option<String>) {
    let mut w = GlobalConfig::write().await;
    let (root_ca_cert, client_cert, client_key) = certificate_loader().await;
    w.settings.certificate.root_ca = root_ca_cert;
    w.settings.certificate.client_cert = client_cert;
    w.settings.certificate.client_key = client_key;
    w.settings.server.ca_server = mca_ip.unwrap_or_else(|| DEFAULT_CA.to_string());
    w.settings.server.dns_server = mdns_info.unwrap_or_else(|| DEFAULT_DNS.to_string());
    tracing::info!("GlobalsConfig 重新載入完成");
}
