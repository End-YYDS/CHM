#[cfg(target_family = "unix")]
mod unix_main {
    use agent::{
        config,
        hostd::{proto::HostdServiceServer, HostdGrpcService},
        GlobalConfig, ID, NEED_EXAMPLE,
    };
    use anyhow::{Context, Result};
    use argh::FromArgs;
    use caps::{CapSet, Capability};
    use chm_grpc::tonic::transport::Server;
    use libc::geteuid;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{atomic::Ordering::Relaxed, Arc},
        time::Duration,
    };
    use tokio::{fs, net::UnixListener, signal, sync::Semaphore};
    use tokio_stream::wrappers::UnixListenerStream;
    use tracing::{error, info, warn};
    use tracing_subscriber::EnvFilter;

    #[derive(FromArgs, Debug, Clone)]
    /// HostD 執行參數
    struct Args {
        /// 產生預設設定檔
        #[argh(switch, short = 'i')]
        init_config: bool,
    }

    fn init_tracing() {
        #[cfg(debug_assertions)]
        let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
        #[cfg(not(debug_assertions))]
        let filter = EnvFilter::from_default_env();

        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        init_tracing();

        let args: Args = argh::from_env();
        if args.init_config {
            NEED_EXAMPLE.store(true, Relaxed);
            config().await?;
            info!("預設設定檔已建立，請檢查 {ID}_config.toml.example");
            return Ok(());
        }

        config().await?;
        ensure_root_user().context("確認 HostD 以 root 權限執行")?;
        ensure_firewall_capabilities().context("設定防火牆能力")?;

        let socket_path =
            GlobalConfig::with(|cfg| cfg.extend.socket_path.clone()).display().to_string();
        if let Err(err) = fs::remove_file(&socket_path).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err.into());
            }
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("無法綁定 UNIX socket {}", socket_path))?;
        let _guard = SocketGuard::new(socket_path.clone());
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o770))
            .with_context(|| format!("設定 socket 權限失敗 {}", socket_path))?;

        let concurrency = GlobalConfig::with(|cfg| cfg.extend.file_concurrency).max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let command_timeout = Duration::from_secs(
            GlobalConfig::with(|cfg| cfg.extend.info_concurrency).max(1) as u64,
        );

        let incoming = UnixListenerStream::new(listener);
        let service = HostdGrpcService::new(Arc::clone(&semaphore), command_timeout);

        info!(
            "[HostD] gRPC 服務啟動於 unix://{socket_path} (max_concurrency: {concurrency}, \
             timeout: {:?})",
            command_timeout
        );

        let shutdown = async {
            match signal::ctrl_c().await {
                Ok(()) => info!("[HostD] 收到 Ctrl-C，準備關閉 gRPC 服務..."),
                Err(err) => error!("[HostD] 等待 Ctrl-C 失敗: {err}"),
            }
        };

        Server::builder()
            .add_service(HostdServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
            .context("HostD gRPC server failed")?;

        info!("[HostD] gRPC 服務已停止");
        Ok(())
    }

    fn ensure_root_user() -> std::io::Result<()> {
        if unsafe { geteuid() } != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "HostD 必須以 root 權限執行",
            ));
        }
        Ok(())
    }

    fn ensure_firewall_capabilities() -> std::io::Result<()> {
        const REQUIRED: [Capability; 2] = [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW];

        let permitted = caps::read(None, CapSet::Permitted)
            .map_err(|e| std::io::Error::other(format!("讀取 permitted capabilities 失敗: {e}")))?;

        let missing: Vec<_> = REQUIRED.iter().filter(|cap| !permitted.contains(cap)).collect();

        if !missing.is_empty() {
            let missing_names =
                missing.into_iter().map(|cap| format!("{cap:?}")).collect::<Vec<_>>().join(", ");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "HostD 缺少必要權限: {missing_names}，請為 HostD 設定 \
                     cap_net_admin,cap_net_raw"
                ),
            ));
        }

        let mut inheritable = caps::read(None, CapSet::Inheritable).map_err(|e| {
            std::io::Error::other(format!("讀取 inheritable capabilities 失敗: {e}"))
        })?;

        let mut inheritable_changed = false;
        for cap in REQUIRED.iter() {
            if inheritable.insert(*cap) {
                inheritable_changed = true;
            }
        }

        if inheritable_changed {
            caps::set(None, CapSet::Inheritable, &inheritable).map_err(|e| {
                std::io::Error::other(format!("設定 inheritable capabilities 失敗: {e}"))
            })?;
        }

        let mut ambient = caps::read(None, CapSet::Ambient)
            .map_err(|e| std::io::Error::other(format!("讀取 ambient capabilities 失敗: {e}")))?;

        let mut ambient_changed = false;
        for cap in REQUIRED.iter() {
            if ambient.insert(*cap) {
                ambient_changed = true;
            }
        }

        if ambient_changed {
            caps::set(None, CapSet::Ambient, &ambient).map_err(|e| {
                std::io::Error::other(format!("設定 ambient capabilities 失敗: {e}"))
            })?;
        }

        Ok(())
    }

    struct SocketGuard {
        path: String,
    }

    impl SocketGuard {
        fn new(path: String) -> Self {
            Self { path }
        }
    }

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            if self.path.is_empty() {
                return;
            }
            if let Err(err) = std::fs::remove_file(&self.path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!("移除 HostD socket 失敗: {}", err);
                }
            }
        }
    }
}

#[cfg(target_family = "unix")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix_main::run().await
}
