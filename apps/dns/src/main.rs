use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, server_init, software_init, software_init_define,
    BootstrapResp, InitData, ServiceDescriptor, ServiceKind,
};
use chm_grpc::tonic_health::server::health_reporter;
use chm_project_const::ProjectConst;
use dns::{config, CertInfo, GlobalConfig, ID, NEED_EXAMPLE};

use chm_grpc::dns::dns_service_server::DnsServiceServer;
use dns::{
    db::DnsSolver,
    service::{make_dns_interceptor, GrpcRouteInfo, GrpcRouteLayer, MyDnsService},
};
use sqlx::types::ipnetwork::Ipv4Network;
#[cfg(debug_assertions)]
use std::net::Ipv4Addr;
use std::{
    net::SocketAddrV4,
    ops::ControlFlow,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::sync::watch;
use tonic::{
    codec::CompressionEncoding,
    codegen::InterceptedService,
    transport::{Certificate, Identity, ServerTlsConfig},
};

#[derive(Debug, FromArgs)]
/// DNS 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    init_config: bool,
}

software_init_define!(
    kind = ServiceKind::Dns,
    health_name = Some("dns.DnsService".to_string()),
    server = true,
    need_controller = true
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    software_init!(Args);
    let (addr, rootca, key_path, cert_path, _is_controller) = server_init!();
    let (self_uuid, hostname) =
        GlobalConfig::with(|cfg| (cfg.server.unique_id, cfg.server.hostname.clone()));
    tracing::info!("正在啟動DNS...");
    let (cert_update_tx, mut cert_update_rx) = watch::channel(());
    loop {
        let (key, cert) = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
        let identity = Identity::from_pem(cert, key);
        let mut tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(CertUtils::load_cert(&rootca)?.to_pem()?));
        if cfg!(debug_assertions) {
            tls = tls.use_key_log();
        }
        let (health_reporter, health_service) = health_reporter();
        health_reporter.set_serving::<DnsServiceServer<MyDnsService>>().await;
        let mut rx = cert_update_rx.clone();
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
                health_reporter.set_not_serving::<DnsServiceServer<MyDnsService>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        let solver = DnsSolver::new().await?;
        let full_fqdn = format!("{hostname}.chm.com");
        let ip_net = Ipv4Network::new(*addr.ip(), 32)?;
        if solver.add_host(&full_fqdn, ip_net.into(), self_uuid).await.is_err() {
            let dns_uuid = solver.get_uuid_by_hostname(&full_fqdn).await?;
            if let Err(e) = solver.edit_ip(dns_uuid, ip_net.into()).await {
                tracing::warn!("DNS主機IP更新失敗: {}", e);
            }
        }
        let needs = |m: &GrpcRouteInfo| {
            m.service.as_str() == "dns.DnsService"
                && matches!(
                    m.method.as_str(),
                    "AddHost" | "DeleteHost" | "EditUuid" | "EditHostname" | "EditIp"
                )
        };
        let raw_dns = DnsServiceServer::new(MyDnsService::new(solver, cert_update_tx.clone()))
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let dns_svc =
            InterceptedService::new(raw_dns, make_dns_interceptor(controller_args, needs));
        tracing::info!("Starting gRPC server on {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .layer(GrpcRouteLayer)
            .add_service(dns_svc)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);
        if let Err(e) = server.await {
            tracing::error!("[gRPC] 啟動失敗: {e:?}");
        }
        if cert_update_rx.has_changed().unwrap_or(false) {
            tracing::info!("[gRPC] 憑證更新，重新啟動 gRPC 服務");
            let _ = cert_update_rx.borrow_and_update();
            continue;
        }
        break;
    }
    // TODO: 添加CRL檢查
    Ok(())
}
