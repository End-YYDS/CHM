use std::{path::PathBuf, sync::atomic::AtomicBool};

use chm_config_bus::{declare_config, declare_config_bus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub socket_path:      PathBuf,
    #[serde(default = "AgentExtension::default_info_concurrency")]
    pub info_concurrency: usize,
    #[serde(default = "AgentExtension::default_file_concurrency")]
    pub file_concurrency: usize,
    #[serde(default)]
    pub controller:       ControllerSettings,
}

impl AgentExtension {
    fn default_socket_path() -> PathBuf {
        PathBuf::from("/tmp/agent_hostd.sock")
    }

    fn default_info_concurrency() -> usize {
        DEFAULT_INFO_CONCURRENCY
    }

    fn default_file_concurrency() -> usize {
        DEFAULT_FILE_CONCURRENCY
    }
}

impl Default for AgentExtension {
    fn default() -> Self {
        Self {
            socket_path:      Self::default_socket_path(),
            info_concurrency: Self::default_info_concurrency(),
            file_concurrency: Self::default_file_concurrency(),
            controller:       ControllerSettings::default(),
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

pub mod cron_manager;
pub mod dashboard;
pub mod error;
pub mod file_manager;
pub mod firewall;
pub mod log;
pub mod network_config;
pub mod process_manager;
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
pub use process_manager::{
    execute_process_command, process_info_structured, ProcessEntry, ProcessInfo, ProcessStatus,
};
pub use software_package::{
    execute_software_delete, execute_software_install, software_info_structured, PackageStatus,
    SoftwareInventory, SoftwarePackage,
};

#[cfg(unix)]
use std::io::{BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{fs, io};

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

#[derive(Debug, Deserialize)]
pub struct ReturnInfo {
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "Message")]
    pub message:    String,
}

#[cfg(unix)]
pub fn send_to_hostd(real_command: &RealCommand) -> io::Result<String> {
    let socket_path = GlobalConfig::with(|cfg| cfg.extend.socket_path.clone());
    let mut stream = UnixStream::connect(socket_path)?;
    let header = format!("GET={}||{}\n", real_command.is_get, real_command.command);
    stream.write_all(header.as_bytes())?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_to_string(&mut response)?;
    Ok(response.trim().to_string())
}

#[cfg(not(unix))]
pub fn send_to_hostd(_real_command: &RealCommand) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "AgentD 僅支援在 Unix-like 平台執行"))
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

pub fn execute_host_body(body: &str) -> Result<HostCommandOutput, String> {
    let payload = wrap_body_for_host(body);
    let real = RealCommand {
        command:       payload,
        is_get:        false,
        response_kind: ResponseKind::Raw,
    };

    let raw = send_to_hostd(&real).map_err(|e| e.to_string())?;
    parse_status_payload(&raw)
}

pub fn parse_return_info(raw: &str) -> Result<ReturnInfo, String> {
    serde_json::from_str::<ReturnInfo>(raw)
        .map_err(|e| format!("failed to parse ReturnInfo JSON: {}", e))
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
