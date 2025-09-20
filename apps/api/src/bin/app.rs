use actix_web::{middleware, middleware::Logger, App, HttpServer};
use api_server::{config, configure_app, ApiResult, AppState, GlobalConfig, ID, NEED_EXAMPLE};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{declare_init_route, Default_ServerCluster};
use chm_grpc::{
    restful::restful_service_client::RestfulServiceClient,
    tonic::{
        codec::CompressionEncoding,
        transport::{Certificate, ClientTlsConfig, Endpoint},
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    ops::ControlFlow,
    sync::atomic::Ordering::Relaxed,
};
use tracing_subscriber::EnvFilter;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct InitRequest {
    data: String,
}
async fn init_data_handler(
    _req: &HttpRequest,
    data: Json<InitRequest>,
) -> ControlFlow<HttpResponse, ()> {
    dbg!(&data);
    dbg!(_req);
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitRequest);

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
    let (addr, controller_addr, rootca, cert_info, otp_len) = GlobalConfig::with(|cfg| {
        let host: IpAddr =
            cfg.server.host.clone().parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let port = cfg.server.port;
        let controller_addr = cfg.extend.controller.clone();
        let rootca = cfg.certificate.root_ca.clone();
        let cert_info = cfg.certificate.cert_info.clone();
        let otp_len = cfg.server.otp_len;
        (SocketAddr::new(host, port), controller_addr, rootca, cert_info, otp_len)
    });
    let (key, x509_cert) = CertUtils::generate_self_signed_cert(
        cert_info.bits,
        &cert_info.country,
        &cert_info.state,
        &cert_info.locality,
        &cert_info.org,
        &cert_info.cn,
        cert_info.san,
        cert_info.days,
    )
    .map_err(|e| format!("生成自簽憑證失敗: {e}"))?;
    let init_server =
        Default_ServerCluster::new(addr.to_string(), x509_cert, key, None::<String>, otp_len, ID)
            .add_configurer(init_route());
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
        std::fs::read(rootca).expect("讀取 RootCA 憑證失敗"),
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
