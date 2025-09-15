use actix_web::{middleware, middleware::Logger, web, App, HttpServer};
use api_server::{config, configure_app, ApiResult, GlobalConfig, ID, NEED_EXAMPLE};
use chm_grpc::{
    restful::restful_service_client::RestfulServiceClient,
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering::Relaxed,
};
use tracing_subscriber::EnvFilter;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AppState {
    gclient: RestfulServiceClient<Channel>,
}
#[actix_web::main]
async fn main() -> ApiResult<()> {
    let args: Vec<String> = std::env::args().collect();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    let (addr, controller_addr, rootca) = GlobalConfig::with(|cfg| {
        let host: IpAddr =
            cfg.server.host.clone().parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let port = cfg.server.port;
        let controller_addr = cfg.services.controller.clone();
        let rootca = cfg.certificate.root_ca.clone();
        (SocketAddr::new(host, port), controller_addr, rootca)
    });
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(std::fs::read(rootca)?));
    let endpoint = Endpoint::from_shared(controller_addr.clone())
        .map_err(|e| format!("無效的 Controller 地址: {e}"))?
        .timeout(std::time::Duration::from_secs(5))
        .tls_config(tls)?;
    let channel = endpoint.connect().await?;
    let grpc_client = RestfulServiceClient::new(channel);
    // let grpc_client = RestfulServiceClient::connect(controller_addr).await?; //
    // Todo: 從設定檔讀取
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { gclient: grpc_client.clone() }))
            .wrap(middleware::NormalizePath::trim())
            .wrap(Logger::default())
            .configure(configure_app)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}
