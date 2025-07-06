#![allow(unused)]
use chm_project_const::ProjectConst;
use tokio::sync::{OnceCell, RwLock};
#[derive(Debug)]
pub struct GlobalsVar {
    pub root_ca_cert: Option<Vec<u8>>,
    pub client_cert: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    pub mca_info: Option<String>,
}
static GLOBALS: OnceCell<RwLock<GlobalsVar>> = OnceCell::const_new();
pub const DEFAULT: &str = "https://127.0.0.1:50052";

pub async fn globals_lock() -> &'static RwLock<GlobalsVar> {
    GLOBALS
        .get_or_init(|| async {
            RwLock::new(GlobalsVar::try_new().unwrap_or(GlobalsVar {
                root_ca_cert: None,
                client_cert: None,
                client_key: None,
                mca_info: None,
            }))
        })
        .await
}
pub async fn reload_globals() {
    let lock = globals_lock().await;
    let mut w = lock.write().await;

    match GlobalsVar::try_new() {
        Some(new_cfg) => {
            *w = new_cfg;
            tracing::info!("GlobalsVar 成功重新載入");
        }
        None => {
            tracing::warn!("GlobalsVar 重新載入失敗，保留舊的配置");
            *w = GlobalsVar {
                root_ca_cert: None,
                client_cert: None,
                client_key: None,
                mca_info: Some(DEFAULT.to_string()),
            };
        }
    }
}
impl GlobalsVar {
    pub fn try_new() -> Option<Self> {
        let cert_path = ProjectConst::certs_path();
        let root_ca_cert = std::fs::read(cert_path.join("rootCA.pem")).ok()?;
        let client_cert = std::fs::read(cert_path.join("controller.pem")).ok()?;
        let client_key = std::fs::read(cert_path.join("controller.key")).ok()?;
        //TODO: 從Config中讀取 mca_info
        Some(Self {
            root_ca_cert: Some(root_ca_cert),
            client_cert: Some(client_cert),
            client_key: Some(client_key),
            mca_info: Some(DEFAULT.to_string()),
        })
    }
}
