use actix_cors::Cors;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{
    body::MessageBody,
    cookie::{Key, SameSite},
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware,
    middleware::{from_fn, Logger, Next},
    App, Error, FromRequest, HttpServer,
};
use api_server::{
    commons::{ResponseResult, ResponseType},
    config, configure_app, ApiResult, AppState, CertInfo, GlobalConfig, ID, NEED_EXAMPLE,
};
use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, declare_init_route, BootstrapResp, Default_ServerCluster, InitData,
};
use chm_grpc::{
    restful::restful_service_client::RestfulServiceClient,
    tonic::{
        codec::CompressionEncoding,
        transport::{Certificate, ClientTlsConfig, Endpoint, Identity},
    },
};
use chm_project_const::{uuid::Uuid, ProjectConst};
use openssl::ssl::{SslFiletype, SslMethod};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering::Relaxed,
    time::Duration,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, FromArgs)]
/// API 主程式參數
pub struct Cli {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    init_config: bool,
}

#[derive(Debug)]
pub struct InitCarry {
    pub root_ca_path:    PathBuf,
    pub uuid:            Uuid,
    pub server_hostname: String,
    pub server_port:     u16,
    pub private_key:     Vec<u8>,
    pub cert_info:       CertInfo,
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
        Arc::new(Self { root_ca_path, uuid, server_hostname, server_port, private_key, cert_info })
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
            let resp = BootstrapResp {
                uuid: carry.uuid,
                csr_pem,
                server_hostname: carry.server_hostname.clone(),
                server_port: carry.server_port,
            };
            return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
        }
        InitData::Finalize { id, cert_pem, .. } => {
            if id != carry.uuid {
                tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
            }
            if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                tracing::error!("保存憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "保存憑證失敗"));
            }
            tracing::info!("初始化完成，已接收憑證");
        }
    }
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitData,extras = (carry: Arc<InitCarry>));

#[actix_web::main]
async fn main() -> ApiResult<()> {
    let args: Cli = argh::from_env();
    #[cfg(debug_assertions)]
    let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if args.init_config {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    let (
        addr,
        controller_addr,
        rootca,
        cert_info,
        otp_len,
        otp_time,
        self_uuid,
        key_path,
        cert_path,
        frontend_origin,
        cookie_name,
        secure_key_bytes,
        same_site,
        cookie_secure,
    ) = GlobalConfig::with(|cfg| {
        let host: IpAddr =
            cfg.server.host.clone().parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let port = cfg.server.port;
        let controller_addr = cfg.extend.controller.clone();
        let rootca = cfg.certificate.root_ca.clone();
        let cert_info = cfg.certificate.cert_info.clone();
        let otp_len = cfg.server.otp_len;
        let otp_time = cfg.server.otp_time;
        let uuid = cfg.server.unique_id;
        let key_path = cfg.certificate.client_key.clone();
        let cert_path = cfg.certificate.client_cert.clone();
        let frontend_origin = cfg.extend.security.frontend_origin.clone();
        let cookie_name = cfg.extend.security.cookie_name.clone();
        let secure_key =
            chm_password::decode_key64_from_base64(cfg.extend.security.session_key.as_str());
        let same_site = cfg.extend.security.same_site.clone();
        (
            SocketAddr::new(host, port),
            controller_addr,
            rootca,
            cert_info,
            otp_len,
            otp_time,
            uuid,
            key_path,
            cert_path,
            frontend_origin,
            cookie_name,
            secure_key.expect("無效的 Session Key"),
            same_site,
            cfg.extend.security.cookie_secure,
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
        addr.port(),
        key.clone(),
        cert_info.clone(),
    );
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
    let identity = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
    let tls =
        ClientTlsConfig::new().identity(Identity::from_pem(identity.1, identity.0)).ca_certificate(
            Certificate::from_pem(std::fs::read(&rootca).expect("讀取 RootCA 憑證失敗")),
        );
    // TODO: 將EndPoint需要先查詢DNS
    let endpoint = Endpoint::from_shared(controller_addr.clone())
        .map_err(|e| format!("無效的 Controller 地址: {e}"))
        .expect("建立 gRPC Endpoint 失敗")
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(5))
        .tls_config(tls)
        .expect("設定 TLS 失敗");
    let channel = endpoint.connect_lazy();
    let grpc_client = RestfulServiceClient::new(channel)
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);
    GlobalConfig::save_config().await.expect("保存配置檔案失敗");
    let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.set_certificate_file(cert_path, SslFiletype::PEM)?;
    let key = Key::from(&secure_key_bytes);
    fn is_public(req: &ServiceRequest) -> bool {
        let path = req.path();
        let m = req.method().as_str();
        if m == "OPTIONS" {
            return true;
        }
        matches!((m, path), ("POST", "/api/login"))
    }
    async fn auth_md(
        req: ServiceRequest,
        next: Next<impl MessageBody + 'static>,
    ) -> Result<ServiceResponse<impl MessageBody>, Error> {
        if is_public(&req) {
            let res = next.call(req).await?;
            return Ok(res.map_into_left_body());
        }

        let session = match Session::extract(req.request()).await {
            Ok(s) => s,
            Err(_) => {
                let (r, _) = req.into_parts();
                let resp = HttpResponse::Unauthorized().json(ResponseResult {
                    r#type:  ResponseType::Err,
                    message: "Session 取得失敗，請重新登入".to_string(),
                });
                let sr = ServiceResponse::new(r, resp.map_into_right_body());
                return Ok(sr);
            }
        };

        let logged_in = matches!(session.get::<String>("uid"), Ok(Some(_)))
            || matches!(session.get::<i64>("uid"), Ok(Some(_)));

        if !logged_in {
            let (r, _) = req.into_parts();
            let resp = HttpResponse::Unauthorized().json(ResponseResult {
                r#type:  ResponseType::Err,
                message: "驗證失敗，請重新登入".to_string(),
            });
            let sr = ServiceResponse::new(r, resp.map_into_right_body());
            return Ok(sr);
        }

        let res = next.call(req).await?;
        Ok(res.map_into_left_body())
    }
    HttpServer::new(move || {
        let auth_gate = from_fn(auth_md);
        let cors = Cors::default()
            .allowed_origin(&frontend_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![header::CONTENT_TYPE, header::ACCEPT])
            .supports_credentials()
            .max_age(3600);
        let same_site =
            if same_site.eq_ignore_ascii_case("None") { SameSite::None } else { SameSite::Lax };
        let session_mw = SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
            .cookie_name(cookie_name.clone())
            .cookie_secure(cookie_secure)
            .cookie_http_only(true)
            .cookie_same_site(same_site)
            .build();
        App::new()
            .app_data(Data::new(AppState { gclient: grpc_client.clone() }))
            .wrap(middleware::NormalizePath::trim())
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(auth_gate)
            .wrap(session_mw)
            .configure(configure_app)
    })
    .bind_openssl(addr, builder)?
    .run()
    .await?;
    Ok(())
}
