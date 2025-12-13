#[cfg(target_family = "unix")]
mod unix_main {
    use agent::{
        config,
        hostd::{init_firewalld_manager, proto::HostdServiceServer, HostdGrpcService},
        GlobalConfig, ID, NEED_EXAMPLE,
    };
    use anyhow::{anyhow, Context, Result};
    use argh::FromArgs;
    use caps::{CapSet, Capability};
    use chm_grpc::tonic::transport::Server;
    use nix::unistd::{chown, close, geteuid, Gid, Uid};
    use std::{
        env,
        os::unix::{
            fs::PermissionsExt,
            io::{FromRawFd, RawFd},
            net::UnixListener as StdUnixListener,
        },
        path::Path,
        sync::{atomic::Ordering::Relaxed, Arc},
        time::Duration,
    };
    use tokio::{fs, net::UnixListener, signal, sync::Semaphore};
    use tokio_stream::wrappers::UnixListenerStream;
    use tracing::{error, info, warn};
    use uzers::get_group_by_name;

    const SD_LISTEN_FDS_START: RawFd = 3;

    #[derive(FromArgs, Debug, Clone)]
    /// HostD 執行參數
    struct Args {
        /// 產生預設設定檔
        #[argh(switch, short = 'i')]
        init_config: bool,
    }

    fn init_tracing() {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: 之後要將這裡的hostd改成不吃參數的版本
        init_tracing();

        let args: Args = argh::from_env();
        if args.init_config {
            NEED_EXAMPLE.store(true, Relaxed);
            config().await?;
            info!("預設設定檔已建立，請檢查 {ID}_config.toml.example");
            return Ok(());
        }

        config().await?;
        if cfg!(debug_assertions) {
            ensure_root_user().context("確認 HostD 以 root 權限執行")?;
            ensure_firewall_capabilities().context("設定防火牆能力")?;
        }

        let socket_path =
            GlobalConfig::with(|cfg| cfg.extend.socket_path.clone()).display().to_string();
        let (listener, _guard, listener_label) = if !cfg!(debug_assertions) {
            if let Some((systemd_listener, name)) =
                take_systemd_socket().context("取得 systemd socket 失敗")?
            {
                let listener = UnixListener::from_std(systemd_listener)
                    .context("將 systemd socket 轉為非同步監聽器失敗")?;
                (listener, None, format!("unix://{name} (systemd)"))
            } else {
                let (listener, guard) =
                    bind_unix_socket(&socket_path, cfg!(debug_assertions)).await?;
                (listener, Some(guard), format!("unix://{socket_path} (fallback)"))
            }
        } else {
            let (listener, guard) = bind_unix_socket(&socket_path, true).await?;
            (listener, Some(guard), format!("unix://{socket_path}"))
        };

        let concurrency = GlobalConfig::with(|cfg| cfg.extend.file_concurrency).max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let (get_timeout_secs, command_timeout_secs) = GlobalConfig::with(|cfg| {
            (cfg.extend.get_timeout_secs.max(1), cfg.extend.command_timeout_secs.max(1))
        });
        let sysinfo_timeout = Duration::from_secs(get_timeout_secs);
        let command_timeout = Duration::from_secs(command_timeout_secs);
        let firewalld = match init_firewalld_manager().await {
            Ok(mgr) => Some(mgr),
            Err(e) => {
                warn!("初始化 firewalld 失敗: {e}");
                None
            }
        };

        let incoming = UnixListenerStream::new(listener);
        let service = HostdGrpcService::new(
            Arc::clone(&semaphore),
            sysinfo_timeout,
            command_timeout,
            firewalld.clone(),
        );

        info!(
            "[HostD] gRPC 服務啟動於 {listener_label} (max_concurrency: {concurrency}, \
             get_timeout: {:?}, command_timeout: {:?})",
            sysinfo_timeout, command_timeout
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
        if !geteuid().is_root() {
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

    fn take_systemd_socket() -> Result<Option<(StdUnixListener, String)>> {
        let listen_pid_env = match env::var("LISTEN_PID") {
            Ok(val) => val,
            Err(_) => return Ok(None),
        };

        let listen_pid: u32 = listen_pid_env.parse().context("LISTEN_PID 不是有效的數字")?;
        if listen_pid != std::process::id() {
            return Ok(None);
        }

        let listen_fds_env = match env::var("LISTEN_FDS") {
            Ok(val) => val,
            Err(_) => return Ok(None),
        };

        let listen_fds: RawFd = listen_fds_env.parse().context("LISTEN_FDS 不是有效的數字")?;
        if listen_fds <= 0 {
            return Ok(None);
        }

        let fdnames = env::var("LISTEN_FDNAMES").unwrap_or_default();
        let mut names_iter = fdnames.split(':').map(|s| s.trim().to_string());

        let mut primary_fd: Option<RawFd> = None;
        for offset in 0..listen_fds {
            let fd = SD_LISTEN_FDS_START + offset;
            if primary_fd.is_none() {
                primary_fd = Some(fd);
            } else {
                let _ = close(fd);
            }
        }

        unsafe {
            env::remove_var("LISTEN_PID");
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_FDNAMES");
        }

        let fd = match primary_fd {
            Some(fd) => fd,
            None => return Ok(None),
        };

        let label =
            names_iter.next().filter(|s| !s.is_empty()).unwrap_or_else(|| format!("fd:{fd}"));

        let listener = unsafe { StdUnixListener::from_raw_fd(fd) };
        listener.set_nonblocking(true).context("設定 systemd socket nonblocking 失敗")?;

        Ok(Some((listener, label)))
    }

    async fn bind_unix_socket(
        socket_path: &str,
        manage_permissions: bool,
    ) -> Result<(UnixListener, SocketGuard)> {
        if let Err(err) = fs::remove_file(socket_path).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err.into());
            }
        }

        let std_listener = StdUnixListener::bind(socket_path)
            .with_context(|| format!("無法綁定 UNIX socket {}", socket_path))?;
        std_listener
            .set_nonblocking(true)
            .with_context(|| format!("設定 socket {} nonblocking 失敗", socket_path))?;

        if manage_permissions {
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o770))
                .with_context(|| format!("設定 socket 權限失敗 {}", socket_path))?;

            let run_as_group =
                GlobalConfig::with(|cfg| cfg.extend.run_as_group.clone()).trim().to_owned();
            if !run_as_group.is_empty() {
                let group = get_group_by_name(&run_as_group).ok_or_else(|| {
                    anyhow!("設定中的 run_as_group '{}' 在系統中不存在", run_as_group)
                })?;
                chown(
                    Path::new(socket_path),
                    Some(Uid::from_raw(0)),
                    Some(Gid::from_raw(group.gid())),
                )
                .map_err(|err| {
                    anyhow!("設定 socket {} 群組為 {} 失敗: {}", socket_path, run_as_group, err)
                })?;
                info!(
                    "[HostD] socket {} 擁有者已調整為 root:{} (mode 770)",
                    socket_path, run_as_group
                );
            }
        }

        let listener = UnixListener::from_std(std_listener)
            .with_context(|| format!("建立非同步 UNIX listener 失敗 {}", socket_path))?;
        Ok((listener, SocketGuard::new(socket_path.to_string())))
    }
}

#[cfg(target_family = "unix")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix_main::run().await
}
