use crate::{server::restful::ControllerRestfulServer, ConResult, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_grpc::{
    restful::restful_service_server::RestfulServiceServer,
    tonic::{
        codec::CompressionEncoding,
        transport::{Certificate, Identity, Server, ServerTlsConfig},
    },
    tonic_health::server::health_reporter,
};
use std::net::{IpAddr, SocketAddr};
use tokio_util::sync::CancellationToken;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};

pub mod restful;
pub async fn start_grpc(cancel: CancellationToken) -> ConResult<()> {
    let (ca_path, host, port, hostname) = GlobalConfig::with(|cfg| {
        (
            cfg.certificate.root_ca.clone(),
            cfg.server.host.clone(),
            cfg.server.port,
            cfg.server.hostname.clone(),
        )
    });
    let ip: IpAddr = host.parse()?;
    let addr = SocketAddr::new(ip, port);
    tracing::info!("啟動 gRPC 伺服器 在 {addr}");
    // Todo: 憑證重載機制
    let (key, cert) = CertUtils::cert_from_name(&hostname, None)?;
    let ident = Identity::from_pem(cert, key);
    let ca_cert = CertUtils::load_cert(ca_path)?.to_pem()?;
    let tls = ServerTlsConfig::new().identity(ident).client_ca_root(Certificate::from_pem(ca_cert));
    let (health_reporter, health_service) = health_reporter();
    health_reporter.set_serving::<RestfulServiceServer<ControllerRestfulServer>>().await;
    // TODO: 添加CRL 攔截器
    let rest_svc = RestfulServiceServer::new(ControllerRestfulServer::default());
    let shutdown_signal = {
        let health_reporter = health_reporter.clone();
        async move {
            cancel.cancelled().await;
            tracing::info!("[gRPC] 收到外部取消，開始關閉…");
            health_reporter
                .set_not_serving::<RestfulServiceServer<ControllerRestfulServer>>()
                .await;
        }
    };
    let server = Server::builder()
        .layer(
            TraceLayer::new_for_grpc()
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true)),
        )
        .tls_config(tls)?
        .add_service(health_service)
        .add_service(
            rest_svc
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd),
        )
        .serve_with_shutdown(addr, shutdown_signal);
    if let Err(e) = server.await {
        tracing::error!("[gRPC] 啟動失敗: {e:?}");
    }
    Ok(())
}
