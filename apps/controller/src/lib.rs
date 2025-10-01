mod communication;
pub mod first;
mod server;
mod supervisor;
use crate::communication::{ClientHandle, GrpcClients};
pub use crate::{config::config, globals::GlobalConfig};
use argh::FromArgs;
use chm_cluster_utils::{
    init_with, Default_ClientCluster, InitData, ServiceDescriptor, ServiceKind,
};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_project_const::ProjectConst;
use dashmap::DashMap;
use first::first_run;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    io::Write,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};
use url::Url;

pub type ClientMap = HashMap<ServiceKind, ClientHandle>;
pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMcd";
#[cfg(debug_assertions)]
const DEFAULT_PORT: u16 = 50051;
const DEFAULT_OTP_LEN: usize = 6;

#[derive(FromArgs, Debug, Clone)]
/// Controller 主程式參數
pub struct Args {
    #[argh(subcommand)]
    pub cmd: Option<Command>,

    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}

#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand)]
pub enum Command {
    /// 新增服務
    Add(AddService),
    /// 刪除服務
    Remove(RemoveService),
    Serve(Serve),
    Init(Init),
}
impl Default for Command {
    fn default() -> Self {
        Command::Serve(Serve::default())
    }
}

#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand, name = "init")]
/// 啟動服務
pub struct Init {
    /// 目標主機名稱或 IP（接受 https:// 開頭）
    #[argh(option, short = 'H')]
    pub hostip: Option<String>,

    /// OTP 驗證碼
    #[argh(option, short = 'p')]
    pub otp_code: Option<String>,
}

#[derive(FromArgs, Debug, Default, Clone)]
#[argh(subcommand, name = "serve")]
/// 啟動服務
pub struct Serve {}

#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand, name = "add")]
/// 新增服務
pub struct AddService {
    /// 目標主機名稱或 IP（接受 https:// 開頭）
    #[argh(option, short = 'H')]
    pub hostip: Option<String>,

    /// OTP 驗證碼
    #[argh(option, short = 'p')]
    pub otp_code: Option<String>,
}

#[derive(FromArgs, Debug, Clone)]
#[argh(subcommand, name = "remove")]
/// 刪除服務
pub struct RemoveService {
    /// 目標主機名稱或 IP（接受 https:// 開頭）
    #[argh(option, short = 'H')]
    pub hostip: Option<String>,

    /// OTP 驗證碼
    #[argh(option, short = 'p')]
    pub otp_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ControllerExtension {
    #[serde(default)]
    pub services_pool: ServicesPool,
    #[serde(default)]
    pub sign_days:     u32,
}
impl Default for ControllerExtension {
    fn default() -> Self {
        Self { services_pool: Default::default(), sign_days: 10 }
    }
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[serde(flatten)]
    pub services: DashMap<ServiceKind, Vec<ServiceDescriptor>>,
}
declare_config!(extend = crate::ControllerExtension);
declare_config_bus!();

fn ask_for_ca_url() -> Url {
    loop {
        let mut ca_url = String::new();
        print!("請輸入 CA 服務的網址 (必須 https:// 開頭): ");
        io::stdout().flush().unwrap();

        if io::stdin().read_line(&mut ca_url).is_err() {
            eprintln!("讀取輸入時發生錯誤，請重試。");
            continue;
        }
        let ca_url = ca_url.trim();
        match Url::parse(ca_url) {
            Ok(url) if url.scheme() == "https" => {
                return url;
            }
            Ok(_) => {
                eprintln!("必須使用 https:// 開頭，請再試一次。");
            }
            Err(_) => {
                eprintln!("不是合法的完整網址，請再試一次。");
            }
        }
    }
}

pub async fn entry(args: Args) -> ConResult<()> {
    let data_dir = ProjectConst::data_path();
    tracing::debug!("檢查是否為第一次執行...");
    let marker_path = data_dir.join(format!(".{ID}.done"));
    let is_first_run = !marker_path.exists();
    if is_first_run {
        if let Some(Command::Init(Init { hostip, otp_code })) = args.cmd.clone() {
            if is_first_run {
                tracing::debug!("寫入Controller UUID到服務池...");
                GlobalConfig::update_with(|cfg| {
                    let self_hostname = cfg.server.hostname.clone();
                    let self_uuid_port =
                        format!("https://{}:{}", cfg.server.unique_id, cfg.server.port);
                    cfg.extend
                        .services_pool
                        .services
                        .entry(ServiceKind::Controller)
                        .or_default()
                        .append(&mut vec![ServiceDescriptor {
                            kind:        ServiceKind::Controller,
                            uri:         self_uuid_port,
                            health_name: Some("controller.Controller".to_string()),
                            is_server:   false,
                            hostname:    self_hostname.to_string(),
                            uuid:        cfg.server.unique_id,
                        }]);
                });
                GlobalConfig::save_config().await?;
                GlobalConfig::reload_config().await?;
                tracing::debug!("Controller UUID 已寫入服務池");
                let ca_url = hostip
                    .unwrap_or_else(|| ask_for_ca_url().as_str().trim_end_matches('/').to_string());
                first_run(&marker_path, ca_url, otp_code).await?;
                // TODO: 初始化mini_DNS連接
                tracing::debug!("第一次執行檢查完成");
            }
        }
    }

    let gclient = Arc::new(GrpcClients::connect_all().await?);
    match args.cmd.unwrap_or_default() {
        Command::Add(AddService { hostip, otp_code }) => {
            let node = Node::new(hostip, otp_code, gclient.clone());
            tracing::debug!("準備新增服務...");
            node.add().await?;
            tracing::info!("服務新增完成");
            Ok(())
        }
        Command::Remove(RemoveService { .. }) => {
            // Todo: 刪除Config中的配置，及mca憑證吊銷，data/.CHM_API.done刪除

            // let node = Node::new(hostip, otp_code, clients.clone());
            // tracing::debug!("準備刪除服務...");
            // node.remove().await?;
            // tracing::info!("服務刪除完成");
            // return Ok(());
            todo!()
        }
        Command::Serve(Serve {}) | Command::Init(Init { .. }) => {
            tracing::info!("正在啟動Controller...");
            supervisor::run_supervised(gclient.clone()).await?;
            Ok(())
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Node {
    gclient:  Arc<GrpcClients>,
    host:     String,
    otp_code: Option<String>,
    wclient:  Default_ClientCluster,
}
impl Node {
    pub fn new(
        hostip: Option<String>,
        otp_code: Option<String>,
        gclient: Arc<GrpcClients>,
    ) -> Self {
        let host = hostip.unwrap_or_else(|| {
            print!("請輸入目標主機名稱或IP網址(https://開頭): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
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
        tracing::debug!("傳送 Bootstrap 請求到目標服務...");
        let first_step = init_with!(self.wclient, payload, as chm_cluster_utils::BootstrapResp)?;
        tracing::debug!("Bootstrap完成，取得CSR，準備向CA請求簽發憑證...");
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        let ca = self.gclient.ca().ok_or("CA client not initialized")?;
        let certs = ca.sign_certificate(first_step.csr_pem.clone(), sign_days).await?;
        let payload = InitData::Finalize {
            id:        first_step.service_desp.uuid,
            cert_pem:  certs.0,
            chain_pem: certs.1,
        };
        tracing::debug!("傳送 Finalize 請求到目標服務...");
        init_with!(self.wclient, payload)?;
        tracing::debug!("Finalize完成，將服務資訊寫入配置檔...");
        GlobalConfig::update_with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .entry(first_step.service_desp.kind)
                .or_default()
                .append(&mut vec![first_step.service_desp.clone()]);
        });
        GlobalConfig::save_config().await?;
        GlobalConfig::reload_config().await?;
        Ok(())
    }
    pub async fn _remove(&self) -> ConResult<()> {
        Ok(())
    }
}

#[macro_export]
macro_rules! build_clients {
    ($channels:expr, { $($kind:ident => $variant:ident($ctor:path)),+ $(,)? }) => {{
        use std::collections::HashMap;
        let mut out: HashMap<$crate::ServiceKind, $crate::ClientHandle> = HashMap::new();
        $(
            if let Some(ch) = $channels.get(&$crate::ServiceKind::$kind) {
                out.insert($crate::ServiceKind::$kind, $crate::ClientHandle::$variant($ctor(ch.clone())));
            } else {
                ::tracing::warn!(
                    "channel for {:?} not found; skip building client",
                    $crate::ServiceKind::$kind
                );
            }
        )+
        out
    }};
}
