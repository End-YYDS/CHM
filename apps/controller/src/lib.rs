mod communication;
pub mod first;
mod server;
mod supervisor;

use crate::communication::GrpcClients;
pub use crate::{config::config, globals::GlobalConfig};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_project_const::{uuid::Uuid, ProjectConst};
use dashmap::DashMap;
use first::first_run;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicBool,
};

pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMcd";
const DEFAULT_PORT: u16 = 50051;
const DEFAULT_OTP_LEN: usize = 6;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ControllerExtension {
    #[serde(default)]
    pub server_ext:    ServerExtension,
    #[serde(default)]
    pub services_pool: ServicesPool,
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[serde(flatten)]
    pub services_uuid: DashMap<String, Uuid>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerExtension {
    #[serde(default = "ServerExtension::default_dns_server")]
    /// DNS 伺服器地址
    pub dns_server: String,
    #[serde(default = "ServerExtension::default_ca_server")]
    /// mCA 伺服器地址
    pub ca_server:  String,
}
impl Default for ServerExtension {
    fn default() -> Self {
        Self { dns_server: Self::default_dns_server(), ca_server: Self::default_ca_server() }
    }
}
impl ServerExtension {
    fn default_dns_server() -> String {
        let dnsip = if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        };
        "http://".to_string() + &dnsip + ":50053"
    }
    fn default_ca_server() -> String {
        let caip = if !cfg!(debug_assertions) {
            chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string()
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
        };
        "https://".to_string() + &caip + ":50052"
    }
}
declare_config!(extend = crate::ControllerExtension);
declare_config_bus!();

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
        cfg.extend.services_pool.services_uuid.insert(self_hostname, cfg.server.unique_id);
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
