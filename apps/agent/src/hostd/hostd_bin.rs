#[cfg(target_family = "unix")]
mod unix_main {
    use agent::{config, GlobalConfig, ID, NEED_EXAMPLE};
    use anyhow::{Context, Result};
    use argh::FromArgs;
    use caps::{CapSet, Capability};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{atomic::Ordering::Relaxed, Arc},
        time::Duration,
    };
    use tokio::{
        fs,
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{UnixListener, UnixStream},
        sync::{OwnedSemaphorePermit, Semaphore},
    };
    use tracing::{error, info};
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
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o770))
            .with_context(|| format!("設定 socket 權限失敗 {}", socket_path))?;

        let concurrency = GlobalConfig::with(|cfg| cfg.extend.file_concurrency).max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let command_timeout = Duration::from_secs(
            GlobalConfig::with(|cfg| cfg.extend.info_concurrency).max(1) as u64,
        );

        info!(
            "[HostD] 已啟動，等待 AgentD 連線 (socket: {}, max_concurrency: {}, timeout: {:?})",
            socket_path, concurrency, command_timeout
        );

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("[HostD] 接受連線失敗: {err}");
                    continue;
                }
            };

            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(err) => {
                    error!("[HostD] 取得併發鎖失敗: {err}");
                    continue;
                }
            };

            let timeout = command_timeout;
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, timeout, permit).await {
                    error!("[HostD] 處理連線失敗: {err}");
                }
            });
        }
    }

    async fn handle_connection(
        stream: UnixStream,
        timeout: Duration,
        permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        let _permit = permit;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut command_line = String::new();

        if reader.read_line(&mut command_line).await? == 0 {
            return Ok(());
        }

        let trimmed_cmd = command_line.trim();
        let (is_get, actual_cmd) = if let Some((prefix, cmd)) = trimmed_cmd.split_once("||") {
            let flag = prefix.trim_start_matches("GET=").trim().eq_ignore_ascii_case("true");
            (flag, cmd.trim())
        } else {
            (false, trimmed_cmd)
        };

        info!("[HostD] 收到指令: {} (mode: {})", actual_cmd, if is_get { "GET" } else { "CMD" });

        let outcome = if is_get {
            match handle_sysinfo(actual_cmd).await {
                Ok(data) => data,
                Err(err) => {
                    error!("[HostD] sysinfo 失敗: {err}");
                    format!("[HostD] sysinfo execution error: {err}")
                }
            }
        } else {
            match handle_command(actual_cmd, timeout).await {
                Ok(data) => data,
                Err(err) => {
                    error!("[HostD] command 失敗: {err}");
                    format!("[HostD] command execution error: {err}")
                }
            }
        };

        writer.write_all(outcome.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_sysinfo(argument: &str) -> Result<String, String> {
        let payload = argument.to_string();
        tokio::task::spawn_blocking(move || agent::hostd::execute_sysinfo(&payload))
            .await
            .map_err(|err| format!("sysinfo worker panic: {err}"))?
    }

    async fn handle_command(command: &str, timeout: Duration) -> Result<String, String> {
        let payload = command.to_string();
        let task = tokio::task::spawn_blocking(move || agent::hostd::execute_command(&payload));

        tokio::pin!(task);
        tokio::select! {
            result = &mut task => {
                let output = result
                    .map_err(|err| format!("command worker panic: {err}"))?
                    .map_err(|err| err.to_string())?;

                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if !stdout.is_empty() {
                    Ok(stdout)
                } else if !stderr.is_empty() {
                    Ok(stderr)
                } else {
                    Ok(String::new())
                }
            }
            _ = tokio::time::sleep(timeout) => {
                task.abort();
                Err("command execution timed out".to_string())
            }
        }
    }

    fn ensure_firewall_capabilities() -> std::io::Result<()> {
        const REQUIRED: [Capability; 2] = [Capability::CAP_NET_ADMIN, Capability::CAP_NET_RAW];

        let permitted = caps::read(None, CapSet::Permitted).map_err(|e| {
            std::io::Error::other(format!("讀取 permitted capabilities 失敗: {e}"))
        })?;

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

        let mut ambient = caps::read(None, CapSet::Ambient).map_err(|e| {
            std::io::Error::other(format!("讀取 ambient capabilities 失敗: {e}"))
        })?;

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
}

#[cfg(target_family = "unix")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix_main::run().await
}
