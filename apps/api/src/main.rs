use actix_web::{middleware, middleware::Logger, App, HttpServer};
use api_server::{
    config, configure_app, ApiResult, AppState, CertInfo, GlobalConfig, ID, NEED_EXAMPLE,
};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{api_resp, declare_init_route, Default_ServerCluster};
use chm_grpc::{
    restful::restful_service_client::RestfulServiceClient,
    tonic::{
        codec::CompressionEncoding,
        transport::{Certificate, ClientTlsConfig, Endpoint},
    },
};
use chm_project_const::uuid::Uuid;
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering::Relaxed,
};
use tracing_subscriber::EnvFilter;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InitData {
    Bootstrap { root_ca_pem: Vec<u8> }, /* Controller 連線過來之後先傳送root_ca_pem,並且取得API
                                         * uuid 與 csr_pem 與Hostname 及 服務本身的Port */
    Finalize { id: Uuid, cert_pem: Vec<u8>, chain_pem: Vec<Vec<u8>> }, /* 檢查 Controller收到的UUID與自身是否相同，相同才接收憑證 */
}

#[derive(Debug, serde::Serialize)]
pub struct BootstrapResp {
    pub uuid:            Uuid,
    pub csr_pem:         Vec<u8>,
    pub server_hostname: String,
    pub server_port:     u16,
}

#[derive(Debug)]
pub struct InitCarry {
    pub root_ca_path:    PathBuf,
    pub uuid:            Uuid,
    pub server_hostname: String,
    pub server_port:     u16,
    pub private_key:     Vec<u8>,
    pub cert_info:       CertInfo,
    pub cert_pem:        RwLock<Option<Vec<u8>>>,
    pub chain_pem:       RwLock<Option<Vec<Vec<u8>>>>,
}

impl InitCarry {
    pub fn new(
        root_ca_path: PathBuf,
        uuid: Uuid,
        server_hostname: String,
        server_port: u16,
        private_key: Vec<u8>,
        cert_info: CertInfo,
    ) -> Arc<Self> {
        Arc::new(Self {
            root_ca_path,
            uuid,
            server_hostname,
            server_port,
            private_key,
            cert_info,
            cert_pem: RwLock::new(None),
            chain_pem: RwLock::new(None),
        })
    }
}

async fn init_data_handler(
    _req: &HttpRequest,
    Json(data): Json<InitData>,
    carry: Data<Arc<InitCarry>>,
) -> ControlFlow<HttpResponse, ()> {
    match data {
        InitData::Bootstrap { root_ca_pem } => {
            if let Err(e) = tokio::fs::write(&carry.root_ca_path, &root_ca_pem).await {
                tracing::error!("寫入 RootCA 憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
            }
            let csr_pem = match CertUtils::generate_csr(
                carry.private_key.clone(),
                &carry.cert_info.country,
                &carry.cert_info.state,
                &carry.cert_info.locality,
                &carry.cert_info.org,
                &carry.cert_info.cn,
                &carry.cert_info.san,
            ) {
                Ok(csr) => csr,
                Err(e) => {
                    tracing::error!("生成 CSR 失敗: {:?}", e);
                    return ControlFlow::Break(api_resp!(InternalServerError "生成 CSR 失敗"));
                }
            };
            let resp = BootstrapResp {
                uuid: carry.uuid,
                csr_pem,
                server_hostname: carry.server_hostname.clone(),
                server_port: carry.server_port,
            };
            return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
            // TODO: 回傳BootstrapResp
        }
        InitData::Finalize { id, cert_pem, chain_pem } => {
            if id != carry.uuid {
                tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
            }
            {
                let mut cert_lock = carry.cert_pem.write().await;
                *cert_lock = Some(cert_pem);
            }
            {
                let mut chain_lock = carry.chain_pem.write().await;
                *chain_lock = Some(chain_pem);
            }
            tracing::info!("初始化完成，已接收憑證");
        }
    }
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitData,extras = (carry: Arc<InitCarry>));

#[actix_web::main]
async fn main() -> ApiResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let filter = if cfg!(debug_assertions) {
        EnvFilter::from_default_env().add_directive("info".parse().unwrap())
    } else {
        EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    let (addr, controller_addr, rootca, cert_info, otp_len, self_uuid) =
        GlobalConfig::with(|cfg| {
            let host: IpAddr = cfg
                .server
                .host
                .clone()
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            let port = cfg.server.port;
            let controller_addr = cfg.extend.controller.clone();
            let rootca = cfg.certificate.root_ca.clone();
            let cert_info = cfg.certificate.cert_info.clone();
            let otp_len = cfg.server.otp_len;
            let uuid = cfg.server.unique_id;
            (SocketAddr::new(host, port), controller_addr, rootca, cert_info, otp_len, uuid)
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
        addr.ip().to_string(),
        addr.port(),
        key.clone(),
        cert_info.clone(),
    );
    let init_server =
        Default_ServerCluster::new(addr.to_string(), x509_cert, key, None::<String>, otp_len, ID)
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
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(
        std::fs::read(&rootca).expect("讀取 RootCA 憑證失敗"),
    ));
    let endpoint = Endpoint::from_shared(controller_addr.clone())
        .map_err(|e| format!("無效的 Controller 地址: {e}"))
        .expect("建立 gRPC Endpoint 失敗")
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(3))
        .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(std::time::Duration::from_secs(15))
        .keep_alive_timeout(std::time::Duration::from_secs(5))
        .tls_config(tls)
        .expect("設定 TLS 失敗");
    let channel = endpoint.connect_lazy();
    let grpc_client = RestfulServiceClient::new(channel)
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);
    GlobalConfig::save_config().await.expect("保存配置檔案失敗");
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { gclient: grpc_client.clone() }))
            .wrap(middleware::NormalizePath::trim())
            .wrap(Logger::default())
            .configure(configure_app)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}
