use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, software_init, software_init_define, BootstrapResp,
    InitData, ServiceDescriptor, ServiceKind,
};

use chm_grpc::{
    dhcp::dhcp_service_server::DhcpServiceServer,
    tonic::{
        codec::CompressionEncoding,
        codegen::InterceptedService,
        transport::{Certificate, Identity, ServerTlsConfig},
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::ProjectConst;
use dhcp::{config, service::DhcpServiceImpl, CertInfo, GlobalConfig, ID, NEED_EXAMPLE};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::ControlFlow,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::sync::watch;
#[derive(FromArgs, Debug, Clone)]
/// Ldap 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}
software_init_define!(
    kind = ServiceKind::Dhcp,
    health_name = Some("dhcp.DhcpService".to_string()),
    server = true,
    need_controller = true
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (addr, rootca, key_path, cert_path, check_is_controller) = software_init!();
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
        let dhcp_srv = InterceptedService::new(raw_dhcp, check_is_controller(controller_args));
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
