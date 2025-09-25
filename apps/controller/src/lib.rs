mod communication;
pub mod first;
mod server;
mod supervisor;
use crate::communication::GrpcClients;
pub use crate::{config::config, globals::GlobalConfig};
use argh::FromArgs;
use chm_cluster_utils::{init_with, Default_ClientCluster, InitData};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_project_const::ProjectConst;
use dashmap::DashMap;
use first::first_run;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::atomic::AtomicBool,
};

pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMcd";
const DEFAULT_PORT: u16 = 50051;
const DEFAULT_OTP_LEN: usize = 6;

#[derive(FromArgs, Debug)]
/// Controller 主程式參數
pub struct Args {
    #[argh(subcommand)]
    pub cmd: Option<Command>,

    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,

    /// 目標主機名稱
    #[argh(option, short = 'h')]
    pub hostip: Option<String>,

    /// OTP 驗證碼
    #[argh(option, short = 'p')]
    pub otp_code: Option<String>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
    /// 新增服務
    Add(AddService),
    /// 刪除服務
    Remove(RemoveService),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "add")]
/// 新增服務
pub struct AddService {}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "remove")]
/// 刪除服務
pub struct RemoveService {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ControllerExtension {
    #[serde(default)]
    pub server_ext:    ServerExtension,
    #[serde(default)]
    pub services_pool: ServicesPool,
    #[serde(default)]
    pub sign_days:     u32,
}
impl Default for ControllerExtension {
    fn default() -> Self {
        Self {
            server_ext:    Default::default(),
            services_pool: Default::default(),
            sign_days:     10,
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[cfg(debug_assertions)]
    #[serde(flatten)]
    pub services_uuid: DashMap<String, String>,
    #[cfg(not(debug_assertions))]
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
        let mut dns_server = String::from("http://");
        #[cfg(debug_assertions)]
        {
            let s = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
            dns_server.push_str(&s);
            dns_server.push_str(":50053");
        }
        #[cfg(not(debug_assertions))]
        {
            let s = chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .to_string();
            dns_server.push_str(&s);
        }
        dns_server
    }
    fn default_ca_server() -> String {
        #[cfg(debug_assertions)]
        let caip = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
        #[cfg(not(debug_assertions))]
        let caip = chm_dns_resolver::DnsResolver::get_local_ip()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .to_string();
        "https://".to_string() + &caip + ":50052"
    }
}
declare_config!(extend = crate::ControllerExtension);
declare_config_bus!();

pub async fn entry(args: Args) -> ConResult<()> {
    tracing::debug!("檢查資料目錄...");
    let data_dir = ProjectConst::data_path();
    std::fs::create_dir_all(&data_dir)?;
    tracing::debug!("資料目錄已檢查");

    tracing::debug!("寫入Controller UUID到服務池...");
    GlobalConfig::update_with(|cfg| {
        let self_hostname = cfg.server.hostname.clone();
        let self_uuid_port = format!("{}:{}", cfg.server.unique_id, cfg.server.port);
        #[cfg(debug_assertions)]
        cfg.extend.services_pool.services_uuid.insert(self_hostname, self_uuid_port);
        #[cfg(not(debug_assertions))]
        cfg.extend.services_pool.services_uuid.insert(self_hostname, cfg.server.unique_id);
    });
    tracing::debug!("Controller UUID 已寫入服務池");
    tracing::debug!("檢查是否為第一次執行...");
    let marker_path = data_dir.join(format!(".{ID}.done"));
    let is_first_run = !marker_path.exists();
    if is_first_run {
        first_run(&marker_path).await?;
        tracing::debug!("第一次執行檢查完成");
    }
    tracing::debug!("開始執行二階段 Controller...");
    tracing::info!("創建gRPC客戶端");
    let clients = communication::init_channels_all().await?;
    tracing::info!("gRPC客戶端創建完成");
    match args.cmd {
        Some(Command::Add(_)) => {
            let node = Node::new(args.hostip, args.otp_code, clients.clone());
            tracing::info!("準備新增服務...");
            node.add().await?;
            tracing::info!("服務新增完成");
            return Ok(());
        }

        Some(Command::Remove(_)) => {
            let node = Node::new(args.hostip, args.otp_code, clients.clone());
            tracing::info!("準備刪除服務...");
            node.remove().await?;
            // node_action(NodeAction::Remove, args.hostip, args.otp_code).await?;
            tracing::info!("服務刪除完成");
            return Ok(());
        }
        _ => {}
    }
    supervisor::run_supervised(clients).await?;
    tracing::debug!("二階段Controller 執行完成");
    Ok(())
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Node {
    gclient:  GrpcClients,
    host:     String,
    otp_code: Option<String>,
    wclient:  Default_ClientCluster,
}
impl Node {
    pub fn new(hostip: Option<String>, otp_code: Option<String>, gclient: GrpcClients) -> Self {
        let host = hostip.unwrap_or_else(|| {
            print!("請輸入目標主機名稱或IP網址(https://開頭): ");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            format!("https://{}", input.trim())
        });
        let wclient = Default_ClientCluster::new(
            host.clone(),
            None::<String>,
            None::<PathBuf>,
            None::<PathBuf>,
            None::<PathBuf>,
            otp_code.clone(),
        );
        Self { host, otp_code, gclient, wclient }
    }
    pub async fn add(&self) -> ConResult<()> {
        let root_ca_bytes =
            tokio::fs::read(GlobalConfig::with(|cfg| cfg.certificate.root_ca.clone())).await?;
        let payload = InitData::Bootstrap { root_ca_pem: root_ca_bytes };
        let first_step = init_with!(self.wclient, payload, as chm_cluster_utils::BootstrapResp)?;
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        let certs = self.gclient.ca.sign_certificate(first_step.csr_pem, sign_days).await?;
        let payload = InitData::Finalize {
            id:        first_step.uuid,
            cert_pem:  certs.0,
            chain_pem: certs.1,
        };
        init_with!(self.wclient, payload)?;
        let uuid_port = format!("{}:{}", first_step.uuid, first_step.server_port);
        GlobalConfig::update_with(|cfg| {
            #[cfg(debug_assertions)]
            cfg.extend
                .services_pool
                .services_uuid
                .insert(first_step.server_hostname.clone(), uuid_port.clone());
            #[cfg(not(debug_assertions))]
            cfg.extend
                .services_pool
                .services_uuid
                .insert(first_step.server_hostname.clone(), first_step.uuid);
        });
        Ok(())
    }
    pub async fn remove(&self) -> ConResult<()> {
        Ok(())
    }
}
