#[cfg(unix)]
use agent::drop_privileges;
use agent::{
    config, detect_linux_info, file_concurrency_limit, info_concurrency_limit,
    make_sysinfo_command, send_to_hostd_async,
    service::{AgentGrpcService, FileGrpcService, InfoGrpcService},
    CertInfo, GlobalConfig, ID, NEED_EXAMPLE,
};
use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, server_init, software_init, software_init_define,
    BootstrapResp, InitData, ServiceDescriptor, ServiceKind,
};
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

#[derive(FromArgs, Debug, Clone)]
/// AgentD 執行參數
pub struct Args {
    /// 產生預設設定檔
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}

software_init_define!(
    kind = ServiceKind::Agent,
    health_name = Some("agent.AgentService".to_string()),
    server = true,
    need_controller = true
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    software_init!(Args);
    let (addr, rootca, key_path, cert_path, is_controller) = server_init!();
    let (_cert_update_tx, mut cert_update_rx) = watch::channel(());
    let system = Arc::new(detect_linux_info());
    let hostd_path = GlobalConfig::with(|cfg| cfg.extend.socket_path.clone()).display().to_string();

    let health_command = make_sysinfo_command("cpu_status");
    send_to_hostd_async(&health_command).await.map_err(|err| {
        tracing::error!("[AgentD] HostD 健康檢查失敗: {err}");
        err
    })?;
    tracing::info!("[AgentD] HostD 健康檢查通過");

    #[cfg(unix)]
    {
        let (configured_user, configured_group) = GlobalConfig::with(|cfg| {
            (cfg.extend.run_as_user.clone(), cfg.extend.run_as_group.clone())
        });
        let user = configured_user.trim();
        let group = configured_group.trim();
        if !user.is_empty() {
            if let Err(err) = drop_privileges(user, group) {
                tracing::error!(
                    "[AgentD] 降權至 {}:{} 失敗: {err}",
                    user,
                    if group.is_empty() { "<primary>" } else { group }
                );
                return Err(err.into());
            }
            tracing::info!(
                "[AgentD] 已降權為 {}:{}",
                user,
                if group.is_empty() { "<primary>" } else { group }
            );
        }
    }

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
            InterceptedService::new(raw_agent, is_controller(controller_args.clone()));
        let info_service =
            InterceptedService::new(raw_info, is_controller(controller_args.clone()));
        let file_service = InterceptedService::new(raw_file, is_controller(controller_args));

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
