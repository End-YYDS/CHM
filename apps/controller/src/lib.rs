mod communication;
pub mod first;
mod server;
mod supervisor;
use crate::communication::{ClientHandle, GrpcClients};
pub use crate::{config::config, globals::GlobalConfig};
use argh::FromArgs;
use chm_cluster_utils::{
    atomic_write, init_with, Default_ClientCluster, InitData, ServiceDescriptor, ServiceKind,
};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_project_const::ProjectConst;
use dashmap::DashMap;
use first::first_run;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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
const DEFAULT_WARN_THRESHOLD: f64 = 0.5;
const DEFAULT_DANG_THRESHOLD: f64 = 0.8;

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
    /// 憑證主機名稱或 IP（接受 https:// 開頭）
    #[argh(option, short = 'H')]
    pub hostip: Option<String>,

    /// 憑證主機OTP 驗證碼
    #[argh(option, short = 'c')]
    pub ca_otp_code:  Option<String>,
    /// DNS主機OTP 驗證碼
    #[argh(option, short = 'd')]
    pub dns_otp_code: Option<String>,
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
    pub alert_config:  AlertConfig,
    #[serde(default)]
    pub sign_days:     u32,
}
impl Default for ControllerExtension {
    fn default() -> Self {
        Self {
            services_pool: Default::default(),
            alert_config:  Default::default(),
            sign_days:     10,
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[serde(flatten)]
    pub services: DashMap<ServiceKind, HashSet<ServiceDescriptor>>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlertConfig {
    #[serde(default = "AlertConfig::default_warn_threshold")]
    pub cpu_warn_threshold:  f64,
    #[serde(default = "AlertConfig::default_dang_threshold")]
    pub cpu_dang_threshold:  f64,
    #[serde(default = "AlertConfig::default_warn_threshold")]
    pub mem_warn_threshold:  f64,
    #[serde(default = "AlertConfig::default_dang_threshold")]
    pub mem_dang_threshold:  f64,
    #[serde(default = "AlertConfig::default_warn_threshold")]
    pub disk_warn_threshold: f64,
    #[serde(default = "AlertConfig::default_dang_threshold")]
    pub disk_dang_threshold: f64,
}
impl Default for AlertConfig {
    fn default() -> Self {
        AlertConfig {
            cpu_warn_threshold:  AlertConfig::default_warn_threshold(),
            cpu_dang_threshold:  AlertConfig::default_dang_threshold(),
            mem_warn_threshold:  AlertConfig::default_warn_threshold(),
            mem_dang_threshold:  AlertConfig::default_dang_threshold(),
            disk_warn_threshold: AlertConfig::default_warn_threshold(),
            disk_dang_threshold: AlertConfig::default_dang_threshold(),
        }
    }
}
impl AlertConfig {
    fn default_warn_threshold() -> f64 {
        DEFAULT_WARN_THRESHOLD
    }
    fn default_dang_threshold() -> f64 {
        DEFAULT_DANG_THRESHOLD
    }
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
    let config = GlobalConfig::with(|cfg| {
        (
            Some(cfg.certificate.client_cert.clone()),
            Some(cfg.certificate.client_key.clone()),
            Some(cfg.certificate.root_ca.clone()),
        )
    });
    if let Some(Command::Init(Init { hostip, ca_otp_code, dns_otp_code })) = args.cmd.clone() {
        return if is_first_run {
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
                    .insert(ServiceDescriptor {
                        kind:        ServiceKind::Controller,
                        uri:         self_uuid_port,
                        health_name: Some("controller.Controller".to_string()),
                        is_server:   false,
                        hostname:    self_hostname.to_string(),
                        uuid:        cfg.server.unique_id,
                    });
            });
            GlobalConfig::save_config().await?;
            GlobalConfig::reload_config().await?;
            tracing::debug!("Controller UUID 已寫入服務池");
            let (has_ca, has_dns) = GlobalConfig::with(|cfg| {
                let m = &cfg.extend.services_pool.services;
                let has_ca = m.get(&ServiceKind::Mca).map(|v| !v.is_empty()).unwrap_or(false);
                let has_dns = m.get(&ServiceKind::Dns).map(|v| !v.is_empty()).unwrap_or(false);
                (has_ca, has_dns)
            });
            if !has_ca {
                let ca_url = hostip
                    .unwrap_or_else(|| ask_for_ca_url().as_str().trim_end_matches('/').to_string());
                first_run(ca_url, ca_otp_code).await?;
            }
            if !has_dns {
                let dns_server = GlobalConfig::with(|cfg| cfg.server.dns_server.clone());
                let gclient = Arc::new(GrpcClients::connect_all(true).await?);
                let dns_node = Node::new(Some(dns_server), dns_otp_code, gclient, config.clone());
                dns_node.add(true).await?;
            }
            let (controller_name, controller_ip, controller_uuid, ca_desp) =
                GlobalConfig::with(|cfg| {
                    let controller_name = cfg.server.hostname.clone();
                    let controller_ip = cfg.server.host.clone();
                    let controller_uuid = cfg.server.unique_id;
                    let ca_set: Option<HashSet<ServiceDescriptor>> =
                        cfg.extend.services_pool.services.get(&ServiceKind::Mca).map(|r| r.clone());
                    (controller_name, controller_ip, controller_uuid, ca_set)
                });
            let gclient = Arc::new(GrpcClients::connect_all(false).await?);
            let dns_client = gclient.dns().ok_or("DNS client not initialized")?;
            tracing::debug!("將 Controller 資訊加入 DNS 伺服器...");
            {
                let full_fqdn = format!("{controller_name}.chm.com");
                dns_client.add_host(full_fqdn, controller_ip, controller_uuid).await?;
                tracing::debug!("Controller 資訊已加入 DNS 伺服器");
            }
            {
                if let Some(ca_set) = ca_desp {
                    for ca in ca_set.iter() {
                        let full_fqdn = format!("{}.chm.com", ca.hostname);
                        let ca_ip = Url::parse(&ca.uri)
                            .map_err(|e| format!("解析 CA URI 時發生錯誤: {e}"))?
                            .host_str()
                            .ok_or("無法從 CA URI 中取得主機名稱")?
                            .to_string();
                        dns_client.add_host(full_fqdn, ca_ip, ca.uuid).await?;
                        tracing::debug!("CA {} 資訊已加入 DNS 伺服器", ca.hostname);
                    }
                }
            }

            atomic_write(&marker_path, b"done").await?;
            tracing::debug!("第一次執行檢查完成");
            Ok(())
        } else {
            tracing::error!("已經初始化過，無法再次執行 init 指令");
            Ok(())
        };
    }

    let gclient = Arc::new(GrpcClients::connect_all(false).await?);
    match args.cmd.unwrap_or_default() {
        Command::Add(AddService { hostip, otp_code }) => {
            let node = Node::new(hostip, otp_code, gclient.clone(), config.clone());
            tracing::debug!("準備新增服務...");
            node.add(false).await?;
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
        Command::Init(Init { .. }) => Ok(()),
        Command::Serve(Serve {}) => {
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
        config: (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
    ) -> Self {
        let host = hostip.unwrap_or_else(|| {
            print!("請輸入目標主機名稱或IP網址(https://開頭): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            format!("https://{}", input.trim())
        });
        let dns_server = GlobalConfig::with(|cfg| cfg.server.dns_server.clone());
        let wclient = Default_ClientCluster::new(
            host.clone(),
            Some(dns_server),
            config.0,
            config.1,
            config.2,
            otp_code.clone(),
        );
        Self { host, otp_code, gclient, wclient }
    }
    pub async fn add(&self, is_dns: bool) -> ConResult<()> {
        let root_ca_bytes =
            tokio::fs::read(GlobalConfig::with(|cfg| cfg.certificate.root_ca.clone())).await?;
        let payload = InitData::Bootstrap {
            root_ca_pem: root_ca_bytes,
            con_uuid:    GlobalConfig::with(|cfg| cfg.server.unique_id),
        };
        tracing::debug!("傳送 Bootstrap 請求到目標服務...");
        let first_step = init_with!(self.wclient, payload, as chm_cluster_utils::BootstrapResp)?;
        tracing::debug!("Bootstrap完成，取得CSR，準備向CA請求簽發憑證...");
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        let ca = self.gclient.ca().ok_or("CA client not initialized")?;
        let certs = ca.sign_certificate(first_step.csr_pem.clone(), sign_days).await?;
        let (controller_cert, controller_uuid) =
            GlobalConfig::with(|cfg| (cfg.certificate.client_cert.clone(), cfg.server.unique_id));
        let controller_pem = tokio::fs::read(controller_cert).await?;
        let payload = InitData::Finalize {
            id: first_step.service_desp.uuid,
            cert_pem: certs.0,
            chain_pem: certs.1,
            controller_pem,
            controller_uuid,
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
                .insert(first_step.service_desp.clone());
        });
        GlobalConfig::save_config().await?;
        GlobalConfig::reload_config().await?;
        if !is_dns {
            tracing::debug!("將服務資訊加入 DNS 伺服器...");
            let dns_client = self.gclient.dns().ok_or("DNS client not initialized")?;
            let full_fqdn = format!("{}.chm.com", first_step.service_desp.hostname);
            dns_client
                .add_host(
                    full_fqdn,
                    first_step.socket.ip().to_string(),
                    first_step.service_desp.uuid,
                )
                .await?;
            tracing::info!("服務資訊已加入 DNS 伺服器");
        }
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
