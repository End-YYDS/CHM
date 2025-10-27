use agentd::{
    config, detect_linux_info, file_concurrency_limit,
    grpc::{AgentGrpcService, FileGrpcService, InfoGrpcService},
    hostd_socket_path, info_concurrency_limit, CertInfo, GlobalConfig, ID, NEED_EXAMPLE,
};
use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::_reexports::{Data, HttpRequest, HttpResponse, Json};
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, BootstrapResp, Default_ServerCluster, InitData,
    ServiceDescriptor, ServiceKind,
};
use chm_config_bus::_reexports::Uuid;
use chm_grpc::{
    agent::{
        agent_file_service_server::AgentFileServiceServer,
        agent_info_service_server::AgentInfoServiceServer,
        agent_service_server::AgentServiceServer,
    },
    tonic::{
        codec::CompressionEncoding,
        codegen::InterceptedService,
        transport::{Certificate, Identity, ServerTlsConfig},
        Request, Status,
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::ProjectConst;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::ControlFlow,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(FromArgs, Debug, Clone)]
/// AgentD 執行參數
pub struct Args {
    /// 產生預設設定檔
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}

#[derive(Debug)]
pub struct InitCarry {
    pub root_ca_path: PathBuf,
    pub uuid: Uuid,
    pub server_hostname: String,
    pub server_addr: SocketAddrV4,
    pub private_key: Vec<u8>,
    pub cert_info: CertInfo,
}

impl InitCarry {
    pub fn new(
        root_ca_path: PathBuf,
        uuid: Uuid,
        server_hostname: String,
        server_addr: SocketAddrV4,
        private_key: Vec<u8>,
        cert_info: CertInfo,
    ) -> Arc<Self> {
        Arc::new(Self { root_ca_path, uuid, server_hostname, server_addr, private_key, cert_info })
    }
}

async fn init_data_handler(
    _req: &HttpRequest,
    Json(data): Json<InitData>,
    carry: Data<Arc<InitCarry>>,
) -> ControlFlow<HttpResponse, ()> {
    match data {
        InitData::Bootstrap { root_ca_pem, .. } => {
            if let Err(e) = atomic_write(&carry.root_ca_path, &root_ca_pem).await {
                tracing::error!("[AgentD:init] 寫入 RootCA 失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 失敗"));
            }
            let mut san_extend = carry.cert_info.san.clone();
            san_extend.push(carry.uuid.to_string());
            let csr_pem = match CertUtils::generate_csr(
                carry.private_key.clone(),
                &carry.cert_info.country,
                &carry.cert_info.state,
                &carry.cert_info.locality,
                ProjectConst::PROJECT_NAME,
                &carry.cert_info.cn,
                san_extend,
            ) {
                Ok(csr) => csr,
                Err(e) => {
                    tracing::error!("[AgentD:init] 產生 CSR 失敗: {:?}", e);
                    return ControlFlow::Break(api_resp!(InternalServerError "產生 CSR 失敗"));
                }
            };
            let service_desp = ServiceDescriptor {
                kind: ServiceKind::Agent,
                uri: format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
                health_name: Some("agent.AgentService".to_string()),
                is_server: true,
                hostname: ID.to_string(),
                uuid: carry.uuid,
            };
            let resp = BootstrapResp { csr_pem, socket: carry.server_addr, service_desp };
            return ControlFlow::Break(api_resp!(ok "初始化通道已建立", resp));
        }
        InitData::Finalize { id, cert_pem, controller_pem, controller_uuid, .. } => {
            if id != carry.uuid {
                tracing::warn!("[AgentD:init] UUID 不符，拒絕完成初始化");
                return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
            }
            if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                tracing::error!("[AgentD:init] 儲存簽章後憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "儲存 Agent 憑證失敗"));
            }
            GlobalConfig::update_with(|cfg| {
                let cert = CertUtils::load_cert_from_bytes(&controller_pem)
                    .expect("讀取 Controller 憑證失敗");
                cfg.extend.controller.serial =
                    CertUtils::cert_serial_sha256(&cert).expect("計算 Controller Serial 失敗");
                cfg.extend.controller.fingerprint = CertUtils::cert_fingerprint_sha256(&cert)
                    .expect("計算 Controller Fingerprint 失敗");
                cfg.extend.controller.uuid = controller_uuid;
            });
            if let Err(e) = GlobalConfig::save_config().await {
                tracing::error!("[AgentD:init] 儲存設定失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "儲存設定失敗"));
            }
            if let Err(e) = GlobalConfig::reload_config().await {
                tracing::error!("[AgentD:init] 重新載入設定失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "重新載入設定失敗"));
            }
            tracing::info!("[AgentD:init] 初始化完成");
        }
    }
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitData, extras = (carry: Arc<InitCarry>));

fn make_agent_interceptor(
    controller_args: (String, String),
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
    move |req: Request<()>| {
        let peer_der_vec =
            req.peer_certs().ok_or_else(|| Status::unauthenticated("未建立 TLS 連線"))?;
        let leaf = peer_der_vec
            .as_ref()
            .as_slice()
            .first()
            .ok_or_else(|| Status::unauthenticated("缺少遠端憑證"))?;

        let x509 = CertUtils::load_cert_from_bytes(leaf)
            .map_err(|_| Status::invalid_argument("遠端憑證 DER 無效"))?;
        let serial = CertUtils::cert_serial_sha256(&x509)
            .map_err(|e| Status::internal(format!("計算 Serial 失敗: {e}")))?;
        let fingerprint = CertUtils::cert_fingerprint_sha256(&x509)
            .map_err(|e| Status::internal(format!("計算 Fingerprint 失敗: {e}")))?;

        if serial != controller_args.0 || fingerprint != controller_args.1 {
            return Err(Status::permission_denied("僅允許 Controller 憑證呼叫 AgentD"));
        }
        Ok(req)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(debug_assertions)]
    let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args: Args = argh::from_env();
    if args.init_config {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("[AgentD] 產生預設設定檔...");
        config().await?;
        tracing::info!("[AgentD] 設定檔已建立，請檢查 {ID}_config.toml.example");
        return Ok(());
    }

    config().await?;
    tracing::info!("[AgentD] 設定檔載入完成");

    let (addr, rootca, cert_info, otp_len, otp_time, self_uuid, key_path, cert_path) =
        GlobalConfig::with(|cfg| {
            let host: Ipv4Addr = cfg.server.host.clone().parse().unwrap_or(Ipv4Addr::LOCALHOST);
            let port = cfg.server.port;
            let rootca = cfg.certificate.root_ca.clone();
            let cert_info = cfg.certificate.cert_info.clone();
            let otp_len = cfg.server.otp_len;
            let otp_time = cfg.server.otp_time;
            let uuid = cfg.server.unique_id;
            let key_path = cfg.certificate.client_key.clone();
            let cert_path = cfg.certificate.client_cert.clone();
            (
                SocketAddrV4::new(host, port),
                rootca,
                cert_info,
                otp_len,
                otp_time,
                uuid,
                key_path,
                cert_path,
            )
        });

    let (key, x509_cert) = CertUtils::generate_self_signed_cert(
        cert_info.bits,
        &cert_info.country,
        &cert_info.state,
        &cert_info.locality,
        &cert_info.org,
        &cert_info.cn,
        &cert_info.san,
        cert_info.days,
    )
    .map_err(|e| format!("產生自簽證書失敗: {e}"))?;

    let carry = InitCarry::new(
        rootca.clone(),
        self_uuid,
        ID.to_string(),
        addr,
        key.clone(),
        cert_info.clone(),
    );

    let init_server =
        Default_ServerCluster::new(addr.to_string(), x509_cert, key, None::<String>, otp_len, ID)
            .with_otp_rotate_every(otp_time)
            .add_configurer(init_route())
            .with_app_data::<InitCarry>(carry.clone());

    tracing::info!("[AgentD] 啟動初始化服務，等待 Controller 完成引導...");
    match init_server.init().await {
        ControlFlow::Continue(()) => {
            tracing::info!("[AgentD] 初始化流程已完成，即將啟動 gRPC 服務");
        }
        ControlFlow::Break(_) => {
            tracing::warn!("[AgentD] 初始化流程被中止 (Ctrl+C)，退出");
            return Ok(());
        }
    }

    tracing::info!("[AgentD] 初始化服務完成，準備啟動 gRPC");
    let (_cert_update_tx, mut cert_update_rx) = watch::channel(());
    let system = Arc::new(detect_linux_info());
    let hostd_path = hostd_socket_path();

    loop {
        let (client_key, client_cert) = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
        let identity = Identity::from_pem(client_cert, client_key);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(CertUtils::load_cert(&rootca)?.to_pem()?));
        let (health_reporter, health_service) = health_reporter();

        health_reporter.set_serving::<AgentServiceServer<AgentGrpcService>>().await;
        health_reporter.set_serving::<AgentInfoServiceServer<InfoGrpcService>>().await;
        health_reporter.set_serving::<AgentFileServiceServer<FileGrpcService>>().await;

        let info_limit = info_concurrency_limit();
        let file_limit = file_concurrency_limit();
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });

        let command_impl = AgentGrpcService::new(Arc::clone(&system));
        let info_impl = InfoGrpcService::new(Arc::clone(&system), info_limit);
        let file_impl = FileGrpcService::new(file_limit);

        let raw_agent = AgentServiceServer::new(command_impl)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let raw_info = AgentInfoServiceServer::new(info_impl)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let raw_file = AgentFileServiceServer::new(file_impl)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);

        let agent_service =
            InterceptedService::new(raw_agent, make_agent_interceptor(controller_args.clone()));
        let info_service =
            InterceptedService::new(raw_info, make_agent_interceptor(controller_args.clone()));
        let file_service =
            InterceptedService::new(raw_file, make_agent_interceptor(controller_args));

        tracing::info!("[AgentD] gRPC 服務啟動於 {addr}，HostD socket: {hostd_path}");

        let mut rx = cert_update_rx.clone();
        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("[AgentD] 收到 Ctrl-C，準備關閉 gRPC 服務...");
                    }
                    Ok(_) = rx.changed() => {
                        tracing::info!("[AgentD] 收到重新載入通知，重啟 gRPC 服務...");
                    }
                }
                health_reporter.set_not_serving::<AgentServiceServer<AgentGrpcService>>().await;
                health_reporter.set_not_serving::<AgentInfoServiceServer<InfoGrpcService>>().await;
                health_reporter.set_not_serving::<AgentFileServiceServer<FileGrpcService>>().await;
            }
        };

        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .add_service(agent_service)
            .add_service(info_service)
            .add_service(file_service)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);

        if let Err(e) = server.await {
            tracing::error!("[AgentD] gRPC 服務啟動失敗: {e:?}");
        }

        if cert_update_rx.has_changed().unwrap_or(false) {
            tracing::info!("[AgentD] gRPC 服務重新啟動完成");
            let _ = cert_update_rx.borrow_and_update();
            continue;
        }
        break;
    }

    Ok(())
}
