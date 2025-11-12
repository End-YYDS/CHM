mod communication;
pub mod first;
mod server;
mod supervisor;
use crate::communication::GrpcClients;
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
    collections::HashSet,
    io,
    io::Write,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};
use url::Url;

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

    /// 服務種類
    #[argh(option, short = 't')]
    pub kind: String,

    /// 確認刪除
    #[argh(switch, short = 'y')]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ControllerExtension {
    #[serde(default)]
    pub services_pool:    ServicesPool,
    #[serde(default = "ControllerExtension::default_sign_days")]
    pub sign_days:        u32,
    #[serde(default = "ControllerExtension::default_concurrency")]
    pub concurrency:      usize,
    #[serde(default = "ControllerExtension::default_service_attempts")]
    pub service_attempts: usize,
}
impl ControllerExtension {
    pub fn default_concurrency() -> usize {
        10
    }
    pub fn default_sign_days() -> u32 {
        10
    }
    pub fn default_service_attempts() -> usize {
        3
    }
}
impl Default for ControllerExtension {
    fn default() -> Self {
        Self {
            services_pool:    Default::default(),
            sign_days:        10,
            concurrency:      10,
            service_attempts: 3,
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ServicesPool {
    #[serde(flatten)]
    pub services: DashMap<ServiceKind, HashSet<ServiceDescriptor>>,
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
            let (has_ca, has_dns, default_port) = GlobalConfig::with(|cfg| {
                let m = &cfg.extend.services_pool.services;
                let has_ca = m.get(&ServiceKind::Mca).map(|v| !v.is_empty()).unwrap_or(false);
                let has_dns = m.get(&ServiceKind::Dns).map(|v| !v.is_empty()).unwrap_or(false);
                let default_port = cfg.server.port;
                (has_ca, has_dns, default_port)
            });
            if !has_ca {
                let mut ca_url = hostip
                    .unwrap_or_else(|| ask_for_ca_url().as_str().trim_end_matches('/').to_string());
                let ip_port = Url::parse(&ca_url).expect("必須為正常Url");
                if ip_port.port().is_none() {
                    let scheme = ip_port.scheme();
                    let new_host = if scheme != "https" {
                        panic!("僅支援 https:// 開頭的網址");
                    } else {
                        ip_port.host_str().expect("無法解析主機名稱").to_string()
                    };
                    ca_url = format!("{scheme}://{new_host}:{default_port}");
                    tracing::warn!(
                        "目標網址未指定 Port，已自動補上預設 Port 11209，新的目標網址為: {ca_url}"
                    );
                }
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
            gclient
                .with_dns_handle(|dns| async move {
                    let full_fqdn = format!("{controller_name}.chm.com");
                    tracing::debug!("將 Controller 資訊加入 DNS 伺服器...");
                    dns.add_host(full_fqdn, controller_ip.clone(), controller_uuid).await
                })
                .await?;
            tracing::debug!("Controller 資訊已加入 DNS 伺服器");
            if let Some(ca_set) = ca_desp {
                for ca in ca_set.iter() {
                    let full_fqdn = format!("{}.chm.com", ca.hostname);
                    let ca_ip = Url::parse(&ca.uri)
                        .map_err(|e| format!("解析 CA URI 時發生錯誤: {e}"))?
                        .host_str()
                        .ok_or("無法從 CA URI 中取得主機名稱")?
                        .to_string();
                    tracing::debug!("將 CA {} 資訊加入 DNS 伺服器", ca.hostname);
                    gclient
                        .with_dns_handle(|dns| async move {
                            dns.add_host(full_fqdn, ca_ip, ca.uuid).await
                        })
                        .await?;
                    tracing::debug!("CA {} 資訊已加入 DNS 伺服器", ca.hostname);
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
        Command::Remove(RemoveService { hostip, otp_code, kind, confirm }) => {
            // Todo: 刪除Config中的配置，及mca憑證吊銷，data/.CHM_API.done刪除
            let node = Node::new(hostip, otp_code, gclient.clone(), config.clone());
            tracing::debug!("準備刪除服務...");
            node.remove(&kind, confirm).await?;
            tracing::info!("服務刪除完成");
            Ok(())
        }
        Command::Init(Init { .. }) => Ok(()),
        Command::Serve(Serve {}) => {
            tracing::info!("正在啟動Controller...");
            supervisor::run_supervised(gclient.clone(), config.clone()).await?;
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
        let default_port = GlobalConfig::with(|cfg| cfg.server.port);
        let mut host = hostip.unwrap_or_else(|| {
            print!("請輸入目標主機名稱或IP網址(https://開頭): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            format!("https://{}", input.trim())
        });
        let ip_port = Url::parse(&host).expect("必須為正常Url");
        if ip_port.port().is_none() {
            let scheme = ip_port.scheme();
            let new_host = if scheme != "https" {
                panic!("僅支援 https:// 開頭的網址");
            } else {
                ip_port.host_str().expect("無法解析主機名稱").to_string()
            };
            host = format!("{scheme}://{new_host}:{default_port}");
            tracing::warn!(
                "目標網址未指定 Port，已自動補上預設 Port 11209，新的目標網址為: {host}"
            );
        }
        let mut dns_server = GlobalConfig::with(|cfg| cfg.server.dns_server.clone());
        let ip_port = Url::parse(&dns_server).expect("必須為正常Url");
        if ip_port.port().is_none() {
            let scheme = ip_port.scheme();
            let new_host = if scheme != "https" {
                panic!("僅支援 https:// 開頭的網址");
            } else {
                ip_port.host_str().expect("無法解析主機名稱").to_string()
            };
            dns_server = format!("{scheme}://{new_host}:{default_port}");
            tracing::warn!(
                "目標網址未指定 Port，已自動補上預設 Port 11209，新的目標網址為: {dns_server}"
            );
        }
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
        let first_step = init_with!(self.wclient, payload, as chm_cluster_utils::BootstrapResp)?; // TODO: 將預設VNI傳送過去
        tracing::debug!("Bootstrap完成，取得CSR，準備向CA請求簽發憑證...");
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        let (cert_pem, chain_pem) = self
            .gclient
            .with_ca_handle(|ca| async move {
                ca.sign_certificate(first_step.csr_pem.clone(), sign_days).await
            })
            .await?;
        let (controller_cert, controller_uuid) =
            GlobalConfig::with(|cfg| (cfg.certificate.client_cert.clone(), cfg.server.unique_id));
        let controller_pem = tokio::fs::read(controller_cert).await?;
        let payload = InitData::Finalize {
            // TODO: 添加 VNI
            // 資訊，需要先與mDHCP問，有什麼可以用，先保留，等到後面交換結束時材真的消耗
            id: first_step.service_desp.uuid,
            cert_pem,
            chain_pem,
            controller_pem,
            controller_uuid,
        };
        // TODO: 消耗標準 -> controller 重啟後送grpc 檢查，確認服務可用,
        // 因為Services的IP 會變成內網IP
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
            let full_fqdn = format!("{}.chm.com", first_step.service_desp.hostname);
            // TODO: 多個服務之間需要有同步機制，避免資料不一致
            // TODO:  IP 會變成mDHCP 分配的內網IP
            self.gclient
                .with_dns_handle(|dns| async move {
                    dns.add_host(
                        full_fqdn,
                        first_step.socket.ip().to_string(),
                        first_step.service_desp.uuid,
                    )
                    .await
                })
                .await?;
            tracing::info!("服務資訊已加入 DNS 伺服器");
        }
        GlobalConfig::reload_config().await?;
        Ok(())
    }
    pub async fn remove(&self, kind: &str, confirm: bool) -> ConResult<()> {
        // TODO: 檢查是否為[CA] [DNS] 服務中最後一個，如果是就看cli有沒有傳confirm參數，
        // TODO: 沒有則禁止刪除只有CLI可以刪除基礎服務
        // 0. 驗證完之後取得服務資訊 (X)
        // 1. 從配置檔刪除服務資訊 (O)
        // 2. 向CA請求吊銷憑證 (O)
        // 3. 刪除data/.{ID}.done標記檔 (X)
        // 4. 從DNS伺服器刪除服務資訊 (O)
        // 5. 通知目標服務刪除本身憑證及資料，並重新啟動初始化程序 (X)
        let kind = kind.parse()?;
        let (want_delete_hostname, want_delete_uuid, want_delete_uri) = GlobalConfig::with(|cfg| {
            let d_uuid = cfg.extend.services_pool.services.get(&kind).and_then(|set| {
                set.iter().find(|desc| desc.uri == self.host).map(|desc| desc.uuid)
            });
            let d_hostname = cfg.extend.services_pool.services.get(&kind).and_then(|set| {
                set.iter().find(|desc| desc.hostname == self.host).map(|desc| desc.hostname.clone())
            });
            let d_uri = cfg.extend.services_pool.services.get(&kind).and_then(|set| {
                set.iter().find(|desc| desc.uri == self.host).map(|desc| desc.uri.clone())
            });
            (d_hostname, d_uuid, d_uri)
        });
        if want_delete_hostname.is_none() || want_delete_uuid.is_none() || want_delete_uri.is_none()
        {
            return Err(format!("在服務池中找不到指定的服務: {kind} @ {}", self.host).into());
        }
        let want_delete_hostname = want_delete_hostname.unwrap();
        let want_delete_uuid = want_delete_uuid.unwrap();
        let want_delete_uri = want_delete_uri.unwrap();
        let want_delete_hostname = format!("{want_delete_hostname}.chm.com");
        GlobalConfig::update_with(|cfg| {
            if matches!(kind, ServiceKind::Mca | ServiceKind::Dns) {
                let services_map = &cfg.extend.services_pool.services;
                if let Some(entry) = services_map.get(&kind) {
                    if entry.len() <= 1 && !confirm {
                        panic!("無法刪除最後一個基礎服務，請使用 -y 參數確認刪除");
                    }
                }
            }
            match cfg.extend.services_pool.services.get_mut(&kind) {
                Some(mut entry) => {
                    entry.retain(|desc| desc.uri != want_delete_uri);
                }
                None => {
                    tracing::error!("服務池中找不到指定的服務種類: {kind}");
                }
            }
        });
        GlobalConfig::save_config().await?;
        GlobalConfig::send_reload();
        let mut revoked_ok_or_not_found = false;
        tracing::debug!("向 CA 伺服器請求吊銷憑證...");
        let get_cert_res = self
            .gclient
            .with_ca_handle(|ca| async move {
                ca.get_certificate_by_common_name(want_delete_hostname.clone()).await
            })
            .await;

        match get_cert_res {
            Ok(Some(cert)) => {
                let serial = cert.serial;
                let ret = self
                    .gclient
                    .with_ca_handle(|ca| async move {
                        ca.mark_certificate_as_revoked(serial, Some("Node Removed!")).await
                    })
                    .await;
                match ret {
                    Ok(true) => {
                        tracing::info!("憑證已吊銷");
                        revoked_ok_or_not_found = true;
                    }
                    Ok(false) => {
                        tracing::warn!("憑證吊銷失敗，請確認憑證是否存在");
                    }
                    Err(e) => {
                        tracing::warn!("吊銷請求失敗：{e}");
                    }
                }
            }
            Ok(None) => {
                tracing::warn!("未找到欲刪除服務的憑證，跳過憑證吊銷步驟");
                revoked_ok_or_not_found = true;
            }
            Err(e) => {
                tracing::warn!("查詢憑證失敗：{e}");
            }
        }
        tracing::debug!("從 DNS 伺服器刪除服務資訊...");
        let deleted = self
            .gclient
            .with_dns_handle(|dns| async move { dns.delete_host(want_delete_uuid).await })
            .await?;
        if deleted {
            tracing::info!("服務資訊已從 DNS 伺服器刪除");
        } else {
            tracing::warn!("服務資訊從 DNS 伺服器刪除失敗，請確認服務是否存在");
        }
        if !revoked_ok_or_not_found && matches!(kind, ServiceKind::Mca) {
            tracing::warn!("CA 憑證未成功吊銷；請手動確認 CA 狀態");
        }
        Ok(())
    }
}
