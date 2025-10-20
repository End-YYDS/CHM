use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, BootstrapResp, Default_ServerCluster, InitData,
    ServiceDescriptor, ServiceKind,
};
use chm_config_bus::_reexports::Uuid;
use chm_grpc::{
    dhcp::dhcp_service_server::DhcpServiceServer,
    tonic::{
        codec::CompressionEncoding,
        codegen::InterceptedService,
        transport::{Certificate, Identity, ServerTlsConfig},
        Request, Status,
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::ProjectConst;
use dhcp::{config, service::DhcpServiceImpl, CertInfo, GlobalConfig, ID, NEED_EXAMPLE};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::atomic::Ordering::Relaxed,
};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(FromArgs, Debug, Clone)]
/// Ldap 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}

#[derive(Debug)]
pub struct InitCarry {
    pub root_ca_path:    PathBuf,
    pub uuid:            Uuid,
    pub server_hostname: String,
    pub server_addr:     SocketAddrV4,
    pub private_key:     Vec<u8>,
    pub cert_info:       CertInfo,
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
                tracing::error!("寫入 RootCA 憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
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
                    tracing::error!("生成 CSR 失敗: {:?}", e);
                    return ControlFlow::Break(api_resp!(InternalServerError "生成 CSR 失敗"));
                }
            };
            let service_desp = ServiceDescriptor {
                kind:        ServiceKind::Dhcp,
                uri:         format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
                health_name: Some("dhcp.DhcpService".to_string()),
                is_server:   true,
                hostname:    ID.to_string(),
                uuid:        carry.uuid,
            };
            let resp = BootstrapResp { csr_pem, socket: carry.server_addr, service_desp };
            return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
        }
        InitData::Finalize { id, cert_pem, controller_pem, controller_uuid, .. } => {
            if id != carry.uuid {
                tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
            }
            if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                tracing::error!("保存憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "保存憑證失敗"));
            }
            GlobalConfig::update_with(|cfg| {
                let cert =
                    CertUtils::load_cert_from_bytes(&controller_pem).expect("無法載入剛接收的憑證");
                cfg.extend.controller.serial =
                    CertUtils::cert_serial_sha256(&cert).expect("無法計算Serial");
                cfg.extend.controller.fingerprint = CertUtils::cert_fingerprint_sha256(&cert)
                    .expect(
                        "
            無法計算fingerprint",
                    );
                cfg.extend.controller.uuid = controller_uuid;
            });
            if let Err(e) = GlobalConfig::save_config().await {
                tracing::error!("保存配置檔案失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "保存配置檔案失敗"));
            }
            if let Err(e) = GlobalConfig::reload_config().await {
                tracing::error!("重新載入配置檔案失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "重新載入配置檔案失敗"));
            }
            tracing::info!("初始化完成，已接收憑證");
        }
    }
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitData,extras = (carry: Arc<InitCarry>));

fn make_dhcp_interceptor(
    controller_args: (String, String),
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
    move |req: Request<()>| {
        let peer_der_vec =
            req.peer_certs().ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
        let leaf = peer_der_vec
            .as_ref()
            .as_slice()
            .first()
            .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;

        let x509 = CertUtils::load_cert_from_bytes(leaf)
            .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))?;
        let serial = CertUtils::cert_serial_sha256(&x509)
            .map_err(|e| Status::internal(format!("Serial sha256 failed: {e}")))?;
        let fingerprint = CertUtils::cert_fingerprint_sha256(&x509)
            .map_err(|e| Status::internal(format!("Fingerprint sha256 failed: {e}")))?;

        if serial != controller_args.0 || fingerprint != controller_args.1 {
            return Err(Status::permission_denied("Only controller cert is allowed"));
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
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    tracing::info!("配置檔案加載完成");
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
    .map_err(|e| format!("生成自簽憑證失敗: {e}"))?;
    let carry = InitCarry::new(
        rootca.clone(),
        self_uuid,
        ID.to_string(),
        addr,
        key.clone(),
        cert_info.clone(),
    );
    // let pool = SqlitePool::connect(&db_url).await?;
    let init_server =
        Default_ServerCluster::new(addr.to_string(), x509_cert, key, None::<String>, otp_len, ID)
            .with_otp_rotate_every(otp_time)
            .add_configurer(init_route())
            .with_app_data::<InitCarry>(carry.clone());
    tracing::info!("啟動初始化 Server，等待 Controller 的初始化請求...");
    match init_server.init().await {
        ControlFlow::Continue(()) => {
            tracing::info!("初始化完成，啟動正式服務...");
        }
        ControlFlow::Break(_) => {
            tracing::warn!("初始化未完成 (Ctrl+C)，程式結束");
            return Ok(());
        }
    }
    tracing::info!("初始化 Server 已結束，繼續啟動正式服務...");
    tracing::info!("正在啟動{ID}...");
    let (_reload_tx, mut reload_rx) = watch::channel(());
    loop {
        let (key, cert) = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(CertUtils::load_cert(&rootca)?.to_pem()?));
        let (health_reporter, health_service) = health_reporter();

        health_reporter.set_serving::<DhcpServiceServer<DhcpServiceImpl>>().await;
        let mut rx = reload_rx.clone();

        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("[gRPC] 收到 Ctrl-C，開始關閉...");
                    }
                    Ok(_) = rx.changed() => {
                        tracing::info!("[gRPC] 憑證更新，開始重新啟動 gRPC...");
                    }
                }
                health_reporter.set_not_serving::<DhcpServiceServer<DhcpServiceImpl>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        let raw_dhcp = DhcpServiceServer::new(DhcpServiceImpl)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let dhcp_srv = InterceptedService::new(raw_dhcp, make_dhcp_interceptor(controller_args));
        tracing::info!("[gRPC] server listening on {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .add_service(dhcp_srv)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);
        if let Err(e) = server.await {
            tracing::debug!("[gRPC] startup failed: {e:?}");
        }
        if reload_rx.has_changed().unwrap_or(false) {
            tracing::info!("[gRPC] restart complete");
            let _ = reload_rx.borrow_and_update();
            continue;
        }
        break;
    }
    Ok(())
}
