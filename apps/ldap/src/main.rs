use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, server_init, software_init, software_init_define,
    BootstrapResp, InitData, ServiceDescriptor, ServiceKind,
};
use chm_grpc::{
    ldap::ldap_service_server::LdapServiceServer,
    tonic::{
        codec::CompressionEncoding,
        codegen::InterceptedService,
        transport::{Certificate, Identity, ServerTlsConfig},
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::ProjectConst;
use ldap::{
    allocator::get_allocator, config, service::MyLdapService, CertInfo, GlobalConfig, ID,
    NEED_EXAMPLE,
};
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
    kind = ServiceKind::Ldap,
    health_name = Some("ldap.LdapService".to_string()),
    server = true,
    need_controller = true
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    software_init!(Args);
    let (addr, rootca, key_path, cert_path, is_controller) = server_init!();
    let (ldap_url, bind_dn, bind_password) = GlobalConfig::with(|cfg| {
        (
            cfg.extend.ldap_settings.url.clone(),
            cfg.extend.ldap_settings.bind_dn.clone(),
            cfg.extend.ldap_settings.bind_password.clone(),
        )
    });
    tracing::info!("正在啟動Ldap...");
    let _ = get_allocator().await;
    let (_cert_update_tx, mut cert_update_rx) = watch::channel(());
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

        health_reporter.set_serving::<LdapServiceServer<MyLdapService>>().await;
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
                health_reporter.set_not_serving::<LdapServiceServer<MyLdapService>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        // TODO: 加入cert_update_tx
        let server = MyLdapService::new(ldap_url.clone(), bind_dn.clone(), bind_password.clone());
        let raw_ldap = LdapServiceServer::new(server)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let ldap_svc = InterceptedService::new(raw_ldap, is_controller(controller_args));
        tracing::info!("Starting gRPC server on {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .add_service(ldap_svc)
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
    Ok(())
}
