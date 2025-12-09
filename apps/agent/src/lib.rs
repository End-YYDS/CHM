use std::{fs, io, path::PathBuf, sync::atomic::AtomicBool};

#[cfg(unix)]
use std::{sync::Arc, time::Duration};

#[cfg(unix)]
use crate::hostd::proto::hostd_service_client::HostdServiceClient;
use chm_config_bus::{declare_config, declare_config_bus};
#[cfg(unix)]
use chm_grpc::tonic::{
    transport::{Channel, Endpoint},
    Code, Status,
};
#[cfg(unix)]
use http::Uri;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use nix::unistd::{geteuid, setgid, setuid, Gid, Uid};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::{
    net::UnixStream,
    sync::{OnceCell, RwLock, Semaphore},
};
#[cfg(unix)]
use tower::service_fn;
use uuid::Uuid;
#[cfg(unix)]
use uzers::{get_group_by_name, get_user_by_name};

pub use crate::{
    config::{config, CertInfo},
    globals::GlobalConfig,
};

pub mod hostd;

// 各 Service 共同需要的常數
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHM_agentd";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50056;
pub const DEFAULT_OTP_LEN: usize = 6;
// ==================================
pub const DEFAULT_INFO_CONCURRENCY: usize = 4;
pub const DEFAULT_FILE_CONCURRENCY: usize = 4;
pub const DEFAULT_HOSTD_GET_CONCURRENCY: usize = 8;
pub const DEFAULT_HOSTD_COMMAND_CONCURRENCY: usize = 2;
pub const DEFAULT_SOFTWARE_CONCURRENCY: usize = 1;
pub const DEFAULT_GET_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControllerSettings {
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub serial:      String,
    #[serde(default = "Uuid::nil")]
    pub uuid:        Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AgentExtension {
    #[serde(default = "AgentExtension::default_socket_path")]
    pub socket_path:               PathBuf,
    #[serde(default = "AgentExtension::default_info_concurrency")]
    pub info_concurrency:          usize,
    #[serde(default = "AgentExtension::default_file_concurrency")]
    pub file_concurrency:          usize,
    #[serde(default = "AgentExtension::default_hostd_get_concurrency")]
    pub hostd_get_concurrency:     usize,
    #[serde(default = "AgentExtension::default_hostd_command_concurrency")]
    pub hostd_command_concurrency: usize,
    #[serde(default = "AgentExtension::default_software_concurrency")]
    pub software_concurrency:      usize,
    #[serde(default = "AgentExtension::default_get_timeout_secs")]
    pub get_timeout_secs:          u64,
    #[serde(default = "AgentExtension::default_command_timeout_secs")]
    pub command_timeout_secs:      u64,
    #[serde(default)]
    pub controller:                ControllerSettings,
    #[serde(default = "AgentExtension::default_run_as_user")]
    pub run_as_user:               String,
    #[serde(default = "AgentExtension::default_run_as_group")]
    pub run_as_group:              String,
}

impl AgentExtension {
    fn default_socket_path() -> PathBuf {
        if cfg!(debug_assertions) {
            PathBuf::from("/tmp/agent_hostd.sock")
        } else {
            PathBuf::from("/run/chm/CHM_hostd.sock")
        }
    }

    fn default_info_concurrency() -> usize {
        DEFAULT_INFO_CONCURRENCY
    }

    fn default_file_concurrency() -> usize {
        DEFAULT_FILE_CONCURRENCY
    }

    fn default_hostd_get_concurrency() -> usize {
        DEFAULT_HOSTD_GET_CONCURRENCY
    }

    fn default_hostd_command_concurrency() -> usize {
        DEFAULT_HOSTD_COMMAND_CONCURRENCY
    }

    fn default_software_concurrency() -> usize {
        DEFAULT_SOFTWARE_CONCURRENCY
    }

    fn default_get_timeout_secs() -> u64 {
        DEFAULT_GET_TIMEOUT_SECS
    }

    fn default_command_timeout_secs() -> u64 {
        DEFAULT_COMMAND_TIMEOUT_SECS
    }

    fn default_run_as_user() -> String {
        "chm".to_string()
    }

    fn default_run_as_group() -> String {
        "chm".to_string()
    }
}

impl Default for AgentExtension {
    fn default() -> Self {
        Self {
            socket_path:               Self::default_socket_path(),
            info_concurrency:          Self::default_info_concurrency(),
            file_concurrency:          Self::default_file_concurrency(),
            hostd_get_concurrency:     Self::default_hostd_get_concurrency(),
            hostd_command_concurrency: Self::default_hostd_command_concurrency(),
            software_concurrency:      Self::default_software_concurrency(),
            get_timeout_secs:          Self::default_get_timeout_secs(),
            command_timeout_secs:      Self::default_command_timeout_secs(),
            controller:                ControllerSettings::default(),
            run_as_user:               Self::default_run_as_user(),
            run_as_group:              Self::default_run_as_group(),
        }
    }
}

declare_config!(extend = crate::AgentExtension);
declare_config_bus!();

pub fn info_concurrency_limit() -> usize {
    let value = crate::globals::GlobalConfig::with(|cfg| cfg.extend.info_concurrency);
    if value == 0 {
        DEFAULT_INFO_CONCURRENCY
    } else {
        value
    }
}

pub fn file_concurrency_limit() -> usize {
    let value = crate::globals::GlobalConfig::with(|cfg| cfg.extend.file_concurrency);
    if value == 0 {
        DEFAULT_FILE_CONCURRENCY
    } else {
        value
    }
}

pub fn hostd_get_concurrency_limit() -> usize {
    let value = crate::globals::GlobalConfig::with(|cfg| cfg.extend.hostd_get_concurrency);
    if value == 0 {
        DEFAULT_HOSTD_GET_CONCURRENCY
    } else {
        value
    }
}

pub fn hostd_command_concurrency_limit() -> usize {
    let value = crate::globals::GlobalConfig::with(|cfg| cfg.extend.hostd_command_concurrency);
    if value == 0 {
        DEFAULT_HOSTD_COMMAND_CONCURRENCY
    } else {
        value
    }
}

pub fn software_concurrency_limit() -> usize {
    let value = crate::globals::GlobalConfig::with(|cfg| cfg.extend.software_concurrency);
    if value == 0 {
        DEFAULT_SOFTWARE_CONCURRENCY
    } else {
        value
    }
}

pub mod cron_manager;
pub mod dashboard;
pub mod error;
pub mod file_manager;
pub mod firewall;
pub mod log;
pub mod network_config;
pub mod pc_manager;
pub mod process_manager;
pub mod servers;
pub mod software_package;

pub mod service;

use chm_password::encode_base64;
pub use cron_manager::{
    cron_info_structured, execute_cron_add, execute_cron_delete, execute_cron_update, CronJob,
    CronJobs, CronSchedule,
};
pub use dashboard::{agent_info_structured, AgentInfo};
pub use file_manager::{
    file_pdir_download, file_pdir_upload, pdir_info_structured, DirectoryEntry, ParentDirectory,
    SizeUnit,
};
pub use firewall::{
    execute_firewall_add, execute_firewall_delete, execute_firewall_edit_policy,
    execute_firewall_edit_status, firewall_info_structured, FirewallChain, FirewallPolicy,
    FirewallRule, FirewallStatus, FirewallStatusState,
};
pub use log::{log_info_structured, log_query_structured, LogEntry, Logs};
pub use network_config::{
    dns_info_structured, execute_netif_add, execute_netif_delete, execute_netif_toggle,
    execute_route_add, execute_route_delete, netif_info_structured, route_info_structured, DnsInfo,
    NetworkInterfaceInfo, NetworkInterfaceState, NetworkInterfaceType, NetworkInterfaces,
    RouteEntry, RouteTable,
};
pub use pc_manager::{execute_reboot, execute_shutdown};
pub use process_manager::{
    execute_process_command, process_info_structured, ProcessAction, ProcessEntry, ProcessInfo,
    ProcessStatus,
};
pub use servers::{
    execute_server_apache_action, get_server_apache, get_server_install, get_server_noninstall,
    ApacheAccessLogEntry, ApacheAction, ApacheDate, ApacheErrorLogEntry, ApacheLogLevel,
    ApacheLogs, ApacheMonth, ApacheServerInfo, ApacheStatus, ApacheTime, ApacheWeek,
    ServerHostInfo, ServerStatus,
};
pub use software_package::{
    execute_software_delete, execute_software_install, software_info_structured, PackageStatus,
    SoftwareInventory, SoftwarePackage,
};

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os_id:      String,
    pub version_id: String,
}

#[derive(Debug)]
pub struct FamilyCommands {
    pub crontab:             &'static str,
    pub ip:                  &'static str,
    pub iptables_candidates: &'static [&'static str],
}

static IPTABLES_STANDARD: [&str; 2] = ["iptables", "iptables-nft"];
static FAMILY_COMMANDS: FamilyCommands = FamilyCommands {
    crontab:             "crontab",
    ip:                  "ip",
    iptables_candidates: &IPTABLES_STANDARD,
};

/// Detect linux distribution info
pub fn detect_linux_info() -> SystemInfo {
    let content = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut os_id = "linux".to_string();
    let mut version_id = "unknown".to_string();

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("ID=") {
            os_id = val.trim_matches('"').to_string();
        }
        if let Some(val) = line.strip_prefix("VERSION_ID=") {
            version_id = val.trim_matches('"').to_string();
        }
    }

    SystemInfo { os_id: os_id.to_lowercase(), version_id }
}

pub(crate) fn family_commands(_: &SystemInfo) -> &'static FamilyCommands {
    &FAMILY_COMMANDS
}

#[derive(Debug, Clone, Copy)]
pub enum ResponseKind {
    Raw,
    ReturnInfo,
}

#[derive(Debug, Clone)]
pub struct RealCommand {
    pub command:       String,
    pub is_get:        bool,
    pub response_kind: ResponseKind,
}

#[derive(Debug, Clone)]
pub struct HostCommandOutput {
    pub status: i32,
    pub output: String,
}

#[derive(Debug, Clone)]
pub enum ReturnStatus {
    Ok,
    Err,
    Other(String),
}

impl ReturnStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ReturnStatus::Ok => "OK",
            ReturnStatus::Err => "ERR",
            ReturnStatus::Other(value) => value.as_str(),
        }
    }

    fn from_raw(value: &str) -> Self {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("OK") {
            ReturnStatus::Ok
        } else if trimmed.eq_ignore_ascii_case("ERR") {
            ReturnStatus::Err
        } else {
            ReturnStatus::Other(trimmed.to_string())
        }
    }
}

impl Serialize for ReturnStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ReturnStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(ReturnStatus::from_raw(&raw))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReturnInfo {
    #[serde(rename = "Type")]
    pub status:  ReturnStatus,
    #[serde(rename = "Message")]
    pub message: String,
}

#[cfg(unix)]
type HostdClient = HostdServiceClient<Channel>;
#[cfg(unix)]
struct HostdClientPool {
    channel:         RwLock<Option<Channel>>,
    socket_path:     PathBuf,
    get_sem:         Semaphore,
    command_sem:     Semaphore,
    connect_timeout: Duration,
    get_timeout:     Duration,
    command_timeout: Duration,
}

#[cfg(unix)]
impl HostdClientPool {
    fn from_config() -> Self {
        let (socket_path, get_timeout_secs, command_timeout_secs, get_limit, command_limit) =
            GlobalConfig::with(|cfg| {
                (
                    cfg.extend.socket_path.clone(),
                    cfg.extend.get_timeout_secs.max(1),
                    cfg.extend.command_timeout_secs.max(1),
                    cfg.extend.hostd_get_concurrency,
                    cfg.extend.hostd_command_concurrency,
                )
            });

        let get_limit = if get_limit == 0 { DEFAULT_HOSTD_GET_CONCURRENCY } else { get_limit };
        let command_limit =
            if command_limit == 0 { DEFAULT_HOSTD_COMMAND_CONCURRENCY } else { command_limit };

        Self {
            channel: RwLock::new(None),
            socket_path,
            get_sem: Semaphore::new(get_limit),
            command_sem: Semaphore::new(command_limit),
            connect_timeout: Duration::from_secs(5),
            get_timeout: Duration::from_secs(get_timeout_secs),
            command_timeout: Duration::from_secs(command_timeout_secs),
        }
    }

    fn semaphore(&self, is_get: bool) -> &Semaphore {
        if is_get {
            &self.get_sem
        } else {
            &self.command_sem
        }
    }

    async fn make_client(&self) -> io::Result<HostdClient> {
        let channel = self.channel().await?;
        Ok(HostdServiceClient::new(channel))
    }

    async fn channel(&self) -> io::Result<Channel> {
        if let Some(channel) = self.channel.read().await.as_ref() {
            return Ok(channel.clone());
        }
        self.reconnect().await
    }

    async fn reconnect(&self) -> io::Result<Channel> {
        let mut guard = self.channel.write().await;
        if let Some(channel) = guard.as_ref() {
            return Ok(channel.clone());
        }
        let channel = self.build_channel().await?;
        *guard = Some(channel.clone());
        Ok(channel)
    }

    async fn build_channel(&self) -> io::Result<Channel> {
        let path = Arc::new(self.socket_path.clone());
        let endpoint = Endpoint::from_static("http://[::]:50059")
            .connect_timeout(self.connect_timeout)
            .timeout(self.get_timeout.max(self.command_timeout));
        let connector = service_fn(move |_: Uri| {
            let path = Arc::clone(&path);
            async move {
                let stream = UnixStream::connect(&*path).await.map_err(io::Error::other)?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        });

        endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::ConnectionRefused, err))
    }

    async fn invalidate(&self) {
        let mut guard = self.channel.write().await;
        *guard = None;
    }
}

#[cfg(unix)]
static HOSTD_POOL: OnceCell<HostdClientPool> = OnceCell::const_new();

#[cfg(unix)]
fn status_to_io_error(status: Status) -> io::Error {
    let kind = match status.code() {
        Code::NotFound => io::ErrorKind::NotFound,
        Code::PermissionDenied | Code::Unauthenticated => io::ErrorKind::PermissionDenied,
        Code::ResourceExhausted => io::ErrorKind::WouldBlock,
        Code::DeadlineExceeded => io::ErrorKind::TimedOut,
        Code::Unavailable => io::ErrorKind::ConnectionRefused,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, status.message().to_string())
}

#[cfg(unix)]
pub async fn send_to_hostd(real_command: &RealCommand) -> io::Result<String> {
    let pool = HOSTD_POOL.get_or_init(|| async { HostdClientPool::from_config() }).await;
    let permit = pool
        .semaphore(real_command.is_get)
        .acquire()
        .await
        .map_err(|_| io::Error::other("HostD semaphore closed"))?;

    let mut client = pool.make_client().await?;
    let timeout = if real_command.is_get { pool.get_timeout } else { pool.command_timeout };

    let result = if real_command.is_get {
        let request = crate::hostd::proto::SysInfoRequest { command: real_command.command.clone() };
        match tokio::time::timeout(timeout, client.run_sys_info(request)).await {
            Ok(Ok(resp)) => Ok(resp.into_inner().output.trim().to_string()),
            Ok(Err(status)) => {
                if matches!(status.code(), Code::Unavailable | Code::Internal) {
                    pool.invalidate().await;
                }
                Err(status_to_io_error(status))
            }
            Err(_) => {
                tracing::warn!("HostD run_sys_info timed out after {:?}", timeout);
                pool.invalidate().await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "HostD RPC timeout"))
            }
        }
    } else {
        let request =
            crate::hostd::proto::HostCommandRequest { command: real_command.command.clone() };
        match tokio::time::timeout(timeout, client.run_host_command(request)).await {
            Ok(Ok(resp)) => {
                let inner = resp.into_inner();
                let payload =
                    if !inner.stdout.trim().is_empty() { inner.stdout } else { inner.stderr };
                Ok(payload.trim().to_string())
            }
            Ok(Err(status)) => {
                if matches!(status.code(), Code::Unavailable | Code::Internal) {
                    pool.invalidate().await;
                }
                Err(status_to_io_error(status))
            }
            Err(_) => {
                tracing::warn!("HostD run_host_command timed out after {:?}", timeout);
                pool.invalidate().await;
                Err(io::Error::new(io::ErrorKind::TimedOut, "HostD RPC timeout"))
            }
        }
    };
    drop(permit);

    result
}

pub fn make_sysinfo_command(keyword: &str) -> RealCommand {
    RealCommand {
        command:       keyword.to_string(),
        is_get:        true,
        response_kind: ResponseKind::Raw,
    }
}

pub fn make_sysinfo_command_with_argument(keyword: &str, argument_json: &str) -> RealCommand {
    let encoded = encode_base64(argument_json);
    let command =
        if encoded.is_empty() { keyword.to_string() } else { format!("{} {}", keyword, encoded) };

    RealCommand { command, is_get: true, response_kind: ResponseKind::Raw }
}

pub async fn execute_host_body(body: &str) -> Result<HostCommandOutput, String> {
    let payload = wrap_body_for_host(body);
    let real = RealCommand {
        command:       payload,
        is_get:        false,
        response_kind: ResponseKind::Raw,
    };

    let raw = send_to_hostd(&real).await.map_err(|e| e.to_string())?;
    parse_status_payload(&raw)
}

#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> io::Result<()> {
    let user = user.trim();
    let group = group.trim();

    if user.is_empty() {
        return Ok(());
    }

    let user_entry = get_user_by_name(user).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("target user {user} not found"))
    })?;

    let target_uid = user_entry.uid();
    let current_uid = geteuid();
    if current_uid.as_raw() == target_uid {
        return Ok(());
    }

    let target_gid = if group.is_empty() {
        user_entry.primary_group_id()
    } else {
        get_group_by_name(group)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("target group {group} not found"))
            })?
            .gid()
    };

    setgid(Gid::from_raw(target_gid)).map_err(nix_error_to_io)?;
    setuid(Uid::from_raw(target_uid)).map_err(nix_error_to_io)?;

    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(_user: &str, _group: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Privilege dropping is only supported on Unix-like platforms",
    ))
}

pub fn parse_return_info(raw: &str) -> Result<ReturnInfo, String> {
    serde_json::from_str::<ReturnInfo>(raw)
        .map_err(|e| format!("failed to parse ReturnInfo JSON: {}", e))
}

#[cfg(unix)]
fn nix_error_to_io(err: nix::errno::Errno) -> io::Error {
    io::Error::from(err)
}

fn wrap_body_for_host(body: &str) -> String {
    let mut normalized = body.trim_end_matches('\n').to_string();
    if !normalized.is_empty() {
        normalized.push('\n');
    }

    let indented = normalized
        .lines()
        .map(|line| if line.is_empty() { "  ".to_string() } else { format!("  {}", line) })
        .collect::<Vec<_>>()
        .join("\n");

    let mut script = String::from("#!/bin/sh\nset -eu\nTMP_OUT=$(mktemp)\nSTATUS=0\n(\n  set -e\n");
    if !indented.is_empty() {
        script.push_str(&indented);
        script.push('\n');
    }
    script.push_str(
        ") >\"$TMP_OUT\" 2>&1 || STATUS=$?\nprintf '__STATUS__:%s\\n' \"$STATUS\"\ncat \
         \"$TMP_OUT\"\nrm -f \"$TMP_OUT\"\nexit 0\n",
    );

    encode_script(&script)
}

fn encode_script(script: &str) -> String {
    let mut script_owned = script.to_string();
    if !script_owned.ends_with('\n') {
        script_owned.push('\n');
    }
    let encoded = encode_base64(script_owned);
    format!("printf '%s' '{}' | base64 -d | sh", encoded)
}

fn parse_status_payload(raw: &str) -> Result<HostCommandOutput, String> {
    let mut lines = raw.lines();
    let status_line =
        lines.next().ok_or_else(|| "missing status line from HostD response".to_string())?;

    const PREFIX: &str = "__STATUS__:";
    if !status_line.starts_with(PREFIX) {
        return Err("unexpected HostD response format".to_string());
    }

    let status_str = status_line[PREFIX.len()..].trim();
    let status = status_str
        .parse::<i32>()
        .map_err(|e| format!("failed to parse HostD status '{}': {}", status_str, e))?;

    let output = lines.collect::<Vec<_>>().join("\n");

    Ok(HostCommandOutput { status, output })
}

pub(crate) fn value_if_specified(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" {
        None
    } else {
        Some(trimmed)
    }
}

pub(crate) fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        "''".to_string()
    } else {
        let escaped = value.replace('\'', "'\\''");
        format!("'{}'", escaped)
    }
}

pub(crate) fn join_shell_args(args: &[String]) -> String {
    args.iter().map(|arg| shell_quote(arg)).collect::<Vec<_>>().join(" ")
}

pub(crate) fn last_non_empty_line(text: &str) -> Option<&str> {
    text.lines().rev().map(str::trim).find(|line| !line.is_empty())
}

pub(crate) fn family_key(sys: &SystemInfo) -> &'static str {
    let os = sys.os_id.to_lowercase();
    if matches!(
        os.as_str(),
        "ubuntu" | "debian" | "kali" | "linuxmint" | "elementary" | "pop" | "zorin"
    ) {
        "debian_like"
    } else if matches!(
        os.as_str(),
        "centos" | "rhel" | "rocky" | "almalinux" | "scientific" | "oracle" | "fedora"
    ) {
        "redhat_like"
    } else {
        "systemd"
    }
}
