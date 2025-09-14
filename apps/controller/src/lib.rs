mod communication;
mod config;
pub mod first;
mod globals;
mod server;
use crate::communication::GrpcClients;
use chm_project_const::ProjectConst;
pub use config::{config, ID, NEED_EXAMPLE};
use first::first_run;
pub use globals::GlobalConfig;

pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AllClients {
    pub grpc: GrpcClients,
    // pub http: reqwest::Client, //TODO: web Client
}

pub async fn entry() -> ConResult<()> {
    tracing::debug!("Controller 啟動中...");
    tracing::debug!("初始化全域設定...");
    config().await?;
    tracing::debug!("全域設定已初始化");
    tracing::debug!("檢查資料目錄...");
    let data_dir = ProjectConst::data_path();
    std::fs::create_dir_all(&data_dir)?;
    tracing::debug!("資料目錄已檢查");
    tracing::debug!("寫入Controller UUID到服務池...");
    {
        let w = GlobalConfig::write().await;
        let self_hostname = w.settings.server.hostname.clone();
        w.settings.services_pool.services_uuid.insert(self_hostname, w.settings.server.unique_id);
    }
    tracing::debug!("Controller UUID 已寫入服務池");
    tracing::debug!("檢查是否為第一次執行...");
    let marker_path = data_dir.join(".controller_first_run.done");
    let is_first_run = !marker_path.exists();
    if is_first_run {
        first_run(&marker_path).await?;
        tracing::debug!("第一次執行檢查完成");
    }
    tracing::debug!("開始執行二階段 Controller...");
    run().await?;
    tracing::debug!("二階段Controller 執行完成");
    Ok(())
}

async fn run() -> ConResult<()> {
    tracing::info!("創建gRPC客戶端");
    let mut clients = communication::init_channel().await?;
    tracing::info!("gRPC客戶端創建完成");
    // Todo: 可以後面所需插入邏輯
    let ret = clients.ca.get_all_certificates().await?;
    tracing::debug!("已獲取 {} 張憑證", ret.len());
    Ok(())
}
