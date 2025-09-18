mod communication;
mod config;
pub mod first;
mod server;
mod supervisor;
use crate::communication::GrpcClients;
use chm_config_bus::declare_config_bus;
use chm_project_const::ProjectConst;
pub use config::{config, ID, NEED_EXAMPLE};
use first::first_run;
pub use globals::GlobalConfig;
pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
declare_config_bus! {
    pub mod globals {
        type Settings = crate::config::Settings;
        const ID: &str = crate::ID;
        save = chm_config_loader::store_config;
        load = chm_config_loader::load_config;
    }
}

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
    GlobalConfig::update_with(|cfg| {
        let self_hostname = cfg.server.hostname.clone();
        cfg.services_pool.services_uuid.insert(self_hostname, cfg.server.unique_id);
    });
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
    let clients = communication::init_channels_all().await?;
    tracing::info!("gRPC客戶端創建完成");
    supervisor::run_supervised(clients).await?;
    Ok(())
}
