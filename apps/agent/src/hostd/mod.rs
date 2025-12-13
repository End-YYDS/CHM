#![cfg(target_family = "unix")]

use base64::{engine::general_purpose, Engine as _};
use chm_firewall::{AppConfig as FirewalldConfig, BasicFirewallConfig, RuleAction, RulesetManager};
use chm_grpc::tonic::{async_trait, Request, Response, Status};
use chrono::{DateTime, Datelike, Local};
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, Prefix},
    schema,
    stmt::{Match, Statement},
};
use pnet::{
    datalink::{interfaces, NetworkInterface},
    ipnetwork::IpNetwork,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{self, BufRead, BufReader},
    net::UdpSocket,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};
use sysinfo::{
    DiskRefreshKind, Disks, MemoryRefreshKind, ProcessRefreshKind, ProcessStatus, System,
};
use tokio::{
    sync::{Mutex, Semaphore},
    task,
};
use uzers::get_user_by_uid;

const META_PREFIX: &str = "# agent_meta:";
const SYSLOG_CANDIDATES: [&str; 2] = ["/var/log/syslog", "/var/log/messages"];
const LOG_ENTRY_LIMIT: usize = 20;
const FIREWALLD_CONFIG_PATH: &str = "config/firewalld.toml";
const FIREWALLD_RULESET_PATH: &str = "config/firewalld_ruleset.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SysinfoKeyword {
    CpuStatus,
    MemoryStatus,
    DiskStatus,
    ProcessList,
    FirewallStatus,
    FirewallAdd,
    FirewallDelete,
    FirewallEditStatus,
    FirewallEditPolicy,
    NetifStatus,
    RouteStatus,
    DnsStatus,
    CronJobs,
    SoftwareStatus,
    LogStatus,
    LogQuery,
    PdirStatus,
    LocalIp,
}

impl SysinfoKeyword {
    fn parse(input: &str) -> Result<Self, String> {
        match input {
            "cpu_status" => Ok(Self::CpuStatus),
            "memory_status" => Ok(Self::MemoryStatus),
            "disk_status" => Ok(Self::DiskStatus),
            "process_list" => Ok(Self::ProcessList),
            "firewall_status" => Ok(Self::FirewallStatus),
            "firewall_add" => Ok(Self::FirewallAdd),
            "firewall_delete" => Ok(Self::FirewallDelete),
            "firewall_edit_status" => Ok(Self::FirewallEditStatus),
            "firewall_edit_policy" => Ok(Self::FirewallEditPolicy),
            "netif_status" => Ok(Self::NetifStatus),
            "route_status" => Ok(Self::RouteStatus),
            "dns_status" => Ok(Self::DnsStatus),
            "cron_jobs" => Ok(Self::CronJobs),
            "software_status" => Ok(Self::SoftwareStatus),
            "log_status" => Ok(Self::LogStatus),
            "log_query" => Ok(Self::LogQuery),
            "pdir_status" => Ok(Self::PdirStatus),
            "local_ip" => Ok(Self::LocalIp),
            other => Err(format!("unknown sysinfo command: {}", other)),
        }
    }
}

fn detect_local_ip() -> Result<String, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("local_ip bind error: {}", e))?;
    socket.connect("1.1.1.1:80").map_err(|e| format!("local_ip connect error: {}", e))?;
    let addr = socket.local_addr().map_err(|e| format!("local_ip read error: {}", e))?;
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip.to_string()),
        _ => Err("local_ip is not IPv4".to_string()),
    }
}

pub mod proto {
    pub use chm_grpc::hostd::{
        hostd_service_server::{HostdService, HostdServiceServer},
        *,
    };
}

#[derive(Clone)]
pub struct HostdGrpcService {
    semaphore:       Arc<Semaphore>,
    command_timeout: Duration,
    sysinfo_timeout: Duration,
    firewalld:       Arc<Mutex<RulesetManager>>,
}

impl HostdGrpcService {
    pub fn new(
        semaphore: Arc<Semaphore>,
        sysinfo_timeout: Duration,
        command_timeout: Duration,
        firewalld: Arc<Mutex<RulesetManager>>,
    ) -> Self {
        Self { semaphore, sysinfo_timeout, command_timeout, firewalld }
    }
}

#[async_trait]
impl proto::HostdService for HostdGrpcService {
    async fn run_sys_info(
        &self,
        request: Request<proto::SysInfoRequest>,
    ) -> Result<Response<proto::SysInfoResponse>, Status> {
        let payload = request.into_inner();
        let command = payload.command;
        if command.trim().is_empty() {
            return Err(Status::invalid_argument("sysinfo command cannot be empty"));
        }
        let firewalld = self.firewalld.clone();
        let handle = task::spawn_blocking(move || execute_sysinfo(&command, firewalld));
        tokio::pin!(handle);
        let join_result = match tokio::time::timeout(self.sysinfo_timeout, &mut handle).await {
            Ok(res) => {
                res.map_err(|err| Status::internal(format!("sysinfo worker panic: {err}")))?
            }
            Err(_) => {
                tracing::error!("HostD run_sys_info timed out after {:?}", self.sysinfo_timeout);
                handle.abort();
                return Err(Status::deadline_exceeded("sysinfo execution timed out"));
            }
        };

        let output = join_result.map_err(|err| {
            let message = err.to_string();
            tracing::error!("HostD sysinfo command failed: {message}");
            Status::internal(message)
        })?;
        Ok(Response::new(proto::SysInfoResponse { output }))
    }

    async fn run_host_command(
        &self,
        request: Request<proto::HostCommandRequest>,
    ) -> Result<Response<proto::HostCommandResponse>, Status> {
        let payload = request.into_inner();
        let command = payload.command;
        if command.trim().is_empty() {
            return Err(Status::invalid_argument("host command cannot be empty"));
        }

        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::resource_exhausted("command semaphore closed"))?;

        let handle = task::spawn_blocking(move || execute_command(&command));
        tokio::pin!(handle);
        let join_result = match tokio::time::timeout(self.command_timeout, &mut handle).await {
            Ok(res) => {
                res.map_err(|err| Status::internal(format!("command worker panic: {err}")))?
            }
            Err(_) => {
                tracing::error!(
                    "HostD run_host_command timed out after {:?}",
                    self.command_timeout
                );
                handle.abort();
                drop(permit);
                return Err(Status::deadline_exceeded("command execution timed out"));
            }
        };
        drop(permit);

        let output = join_result.map_err(|err| {
            let message = err.to_string();
            tracing::error!("HostD run_host_command failed: {message}");
            Status::internal(message)
        })?;
        let status = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok(Response::new(proto::HostCommandResponse { status, stdout, stderr }))
    }
}
fn is_allowed_script(command: &str) -> bool {
    let trimmed = command.trim();
    trimmed.starts_with("printf '")
        && trimmed.contains("| base64 -d | sh")
        && !trimmed.contains(';')
}

/// Run a shell command and return stdout/stderr
pub fn execute_command(command: &str) -> io::Result<Output> {
    if !is_allowed_script(command) {
        tracing::warn!("拒絕執行未授權指令: {command}");
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "command pattern not allowed"));
    }
    Command::new("sh").arg("-c").arg(command).output()
}

/// Execute sysinfo-oriented requests
pub fn execute_sysinfo(
    command: &str,
    firewalld: Arc<Mutex<RulesetManager>>,
) -> Result<String, String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("no sysinfo request provided".to_string());
    }

    let mut parts = trimmed.splitn(2, ' ');
    let keyword_raw = parts.next().ok_or_else(|| "no sysinfo request provided".to_string())?;
    let argument = parts.next().map(str::trim);

    let mut sys = System::new_all();
    sys.refresh_all();

    let keyword = SysinfoKeyword::parse(keyword_raw)?;

    match keyword {
        SysinfoKeyword::CpuStatus => {
            sys.refresh_cpu_usage();
            let cpu_usage = sys.global_cpu_usage();
            Ok(format!("{:.2}", cpu_usage))
        }
        SysinfoKeyword::MemoryStatus => {
            sys.refresh_memory_specifics(MemoryRefreshKind::everything());
            let used = sys.used_memory() as f64;
            let total = sys.total_memory() as f64;
            let percent = if total > 0.0 { (used / total) * 100.0 } else { 0.0 };
            Ok(format!("{:.2}", percent))
        }
        SysinfoKeyword::DiskStatus => {
            let disks = Disks::new_with_refreshed_list_specifics(DiskRefreshKind::everything());
            let mut used: u128 = 0;
            let mut total: u128 = 0;
            for disk in disks.iter() {
                total += disk.total_space() as u128;
                used += (disk.total_space() - disk.available_space()) as u128;
            }
            let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
            Ok(format!("{:.2}", percent))
        }
        SysinfoKeyword::ProcessList => collect_process_info(&mut sys).and_then(|dto| {
            serde_json::to_string(&dto).map_err(|e| format!("failed to encode process info: {}", e))
        }),
        SysinfoKeyword::FirewallStatus => firewall_status(firewalld.clone()).and_then(|status| {
            serde_json::to_string(&status)
                .map_err(|e| format!("failed to encode firewall status: {}", e))
        }),
        SysinfoKeyword::FirewallAdd => {
            let argument =
                argument.ok_or_else(|| "firewall_add requires an argument".to_string())?;
            firewall_add(argument, &firewalld)
        }
        SysinfoKeyword::FirewallDelete => {
            let argument =
                argument.ok_or_else(|| "firewall_delete requires an argument".to_string())?;
            firewall_delete(argument, &firewalld)
        }
        SysinfoKeyword::FirewallEditStatus => {
            let argument =
                argument.ok_or_else(|| "firewall_edit_status requires an argument".to_string())?;
            firewall_edit_status(argument, &firewalld)
        }
        SysinfoKeyword::FirewallEditPolicy => {
            let argument =
                argument.ok_or_else(|| "firewall_edit_policy requires an argument".to_string())?;
            firewall_edit_policy(argument, &firewalld)
        }
        SysinfoKeyword::NetifStatus => collect_network_interfaces().and_then(|dto| {
            serde_json::to_string(&dto)
                .map_err(|e| format!("failed to encode network interfaces: {}", e))
        }),
        SysinfoKeyword::RouteStatus => collect_route_table().and_then(|dto| {
            serde_json::to_string(&dto).map_err(|e| format!("failed to encode route table: {}", e))
        }),
        SysinfoKeyword::DnsStatus => collect_dns_info().and_then(|dto| {
            serde_json::to_string(&dto).map_err(|e| format!("failed to encode dns info: {}", e))
        }),
        SysinfoKeyword::CronJobs => {
            serialize_cron_jobs().map_err(|e| format!("failed to collect cron jobs: {}", e))
        }
        SysinfoKeyword::SoftwareStatus => collect_software_inventory().and_then(|dto| {
            serde_json::to_string(&dto)
                .map_err(|e| format!("failed to encode software inventory: {}", e))
        }),
        SysinfoKeyword::LogStatus => collect_log_entries(None).and_then(|dto| {
            serde_json::to_string(&dto).map_err(|e| format!("failed to encode log entries: {}", e))
        }),
        SysinfoKeyword::LogQuery => {
            let encoded = argument.ok_or_else(|| "log_query requires an argument".to_string())?;
            let query = decode_log_query_argument(encoded)?;
            collect_log_entries(Some((query.search, query.parameter))).and_then(|dto| {
                serde_json::to_string(&dto)
                    .map_err(|e| format!("failed to encode log entries: {}", e))
            })
        }
        SysinfoKeyword::PdirStatus => {
            let directory = match argument {
                Some(encoded) if !encoded.is_empty() => decode_directory_argument(encoded)?,
                _ => "/".to_string(),
            };

            collect_parent_directory(&directory).and_then(|dto| {
                serde_json::to_string(&dto)
                    .map_err(|e| format!("failed to encode directory info: {}", e))
            })
        }
        SysinfoKeyword::LocalIp => detect_local_ip(),
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct CronScheduleDto {
    minute: i32,
    hour:   i32,
    date:   i32,
    month:  i32,
    week:   i32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct CronJobDto {
    id:       String,
    name:     String,
    command:  String,
    schedule: CronScheduleDto,
    username: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CronJobsDto {
    jobs:   Vec<CronJobDto>,
    length: usize,
}

#[derive(Serialize, Deserialize)]
struct CronMeta {
    id:   String,
    name: String,
}

#[derive(Deserialize)]
struct DirectoryArgumentDto {
    #[serde(rename = "Directory")]
    directory: Option<String>,
}

#[derive(Serialize)]
struct ParentDirectoryDto {
    #[serde(rename = "Files")]
    files:  BTreeMap<String, DirectoryEntryDto>,
    #[serde(rename = "Length")]
    length: usize,
}

#[derive(Serialize)]
struct DirectoryEntryDto {
    #[serde(rename = "Size")]
    size:     f64,
    #[serde(rename = "Unit")]
    unit:     String,
    #[serde(rename = "Owner")]
    owner:    String,
    #[serde(rename = "Mode")]
    mode:     String,
    #[serde(rename = "Modified")]
    modified: String,
}

#[derive(Serialize)]
struct SoftwareInventoryDto {
    #[serde(rename = "Packages")]
    packages: BTreeMap<String, SoftwarePackageDto>,
}

#[derive(Serialize)]
struct SoftwarePackageDto {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Status")]
    status:  String,
}

#[derive(Serialize)]
struct LogsDto {
    #[serde(rename = "Logs")]
    logs:   BTreeMap<String, LogEntryDto>,
    #[serde(rename = "Length")]
    length: usize,
}

#[derive(Serialize, Clone)]
struct LogEntryDto {
    #[serde(rename = "Month")]
    month:    String,
    #[serde(rename = "Day")]
    day:      i32,
    #[serde(rename = "Time")]
    time:     String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Type")]
    r#type:   String,
    #[serde(rename = "Messages")]
    messages: String,
}

#[derive(Deserialize)]
struct LogQueryDto {
    #[serde(rename = "Search")]
    search:    LogSearchField,
    #[serde(rename = "Parameter")]
    parameter: String,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
enum LogSearchField {
    Month,
    Day,
    Time,
    Hostname,
    Type,
}

#[derive(Serialize)]
pub struct FirewallStatusDto {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Chains")]
    chains: Vec<FirewallChainDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum FirewallChainArg {
    Input,
    Output,
}

impl FirewallChainArg {
    fn as_str(self) -> &'static str {
        match self {
            FirewallChainArg::Input => "INPUT",
            FirewallChainArg::Output => "OUTPUT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum FirewallTargetArg {
    Accept,
    Drop,
}

impl FirewallTargetArg {
    fn as_str(self) -> &'static str {
        match self {
            FirewallTargetArg::Accept => "ACCEPT",
            FirewallTargetArg::Drop => "DROP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum FirewallStatusArg {
    Active,
    Inactive,
}

#[derive(Serialize)]
pub struct ProcessInfoDto {
    #[serde(rename = "Entries")]
    entries: Vec<ProcessEntryDto>,
    #[serde(rename = "Length")]
    length:  usize,
}

#[derive(Serialize)]
pub struct ProcessEntryDto {
    #[serde(rename = "Name")]
    name:   String,
    #[serde(rename = "Status")]
    status: ProcessStatusDto,
}

#[derive(Serialize)]
pub struct ProcessStatusDto {
    #[serde(rename = "Status")]
    status: bool,
    #[serde(rename = "Boot")]
    boot:   bool,
}

#[derive(Serialize)]
pub struct FirewallChainDto {
    #[serde(rename = "Name")]
    name:         String,
    #[serde(rename = "Policy")]
    policy:       String,
    #[serde(rename = "Rules")]
    rules:        Vec<FirewallRuleDto>,
    #[serde(rename = "Rules_Length")]
    rules_length: usize,
}

#[derive(Serialize)]
pub struct FirewallRuleDto {
    #[serde(rename = "Id")]
    id:            String,
    #[serde(rename = "Target")]
    target:        String,
    #[serde(rename = "Protocol")]
    protocol:      String,
    #[serde(rename = "In")]
    in_interface:  String,
    #[serde(rename = "Out")]
    out_interface: String,
    #[serde(rename = "Source")]
    source:        String,
    #[serde(rename = "Destination")]
    destination:   String,
    #[serde(rename = "Options")]
    options:       String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallAddArg {
    chain:       FirewallChainArg,
    target:      FirewallTargetArg,
    protocol:    String,
    #[serde(rename = "In")]
    in_field:    String,
    #[serde(rename = "Out")]
    out_field:   String,
    source:      String,
    destination: String,
    options:     String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallDeleteArg {
    chain:   FirewallChainArg,
    #[serde(rename = "RuleId")]
    rule_id: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallEditStatusArg {
    status: FirewallStatusArg,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallEditPolicyArg {
    chain:  FirewallChainArg,
    policy: FirewallTargetArg,
}

#[derive(Serialize)]
pub struct NetworkInterfacesDto {
    #[serde(rename = "Networks")]
    networks: BTreeMap<String, NetworkInterfaceDto>,
    #[serde(rename = "Length")]
    length:   usize,
}

#[derive(Serialize)]
pub struct NetworkInterfaceDto {
    #[serde(rename = "Name")]
    name:       String,
    #[serde(rename = "Type")]
    iface_type: String,
    #[serde(rename = "Ipv4")]
    ipv4:       String,
    #[serde(rename = "Netmask")]
    netmask:    String,
    #[serde(rename = "Mac")]
    mac:        String,
    #[serde(rename = "Broadcast")]
    broadcast:  String,
    #[serde(rename = "Mtu")]
    mtu:        u32,
    #[serde(rename = "Status")]
    status:     String,
}

#[derive(Serialize)]
pub struct RouteTableDto {
    #[serde(rename = "Routes")]
    routes: BTreeMap<String, RouteEntryDto>,
    #[serde(rename = "Length")]
    length: usize,
}

#[derive(Serialize)]
pub struct RouteEntryDto {
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "Via")]
    via:         String,
    #[serde(rename = "Dev")]
    dev:         String,
    #[serde(rename = "Proto")]
    proto:       String,
    #[serde(rename = "Metric")]
    metric:      i32,
    #[serde(rename = "Scope")]
    scope:       String,
    #[serde(rename = "Src")]
    src:         String,
}

#[derive(Deserialize)]
struct IpRouteJsonEntry {
    dst:      Option<String>,
    gateway:  Option<String>,
    dev:      Option<String>,
    protocol: Option<String>,
    metric:   Option<i64>,
    scope:    Option<String>,
    prefsrc:  Option<String>,
}

#[derive(Serialize)]
pub struct DnsInfoDto {
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "DNS")]
    dns:      DnsServersDto,
}

#[derive(Serialize)]
pub struct DnsServersDto {
    #[serde(rename = "Primary")]
    primary:   String,
    #[serde(rename = "Secondary")]
    secondary: String,
}

pub fn firewall_status(firewalld: Arc<Mutex<RulesetManager>>) -> Result<FirewallStatusDto, String> {
    firewalld_status(&firewalld)
}

fn firewall_add(argument: &str, manager: &Arc<Mutex<RulesetManager>>) -> Result<String, String> {
    let payload: FirewallAddArg = parse_firewall_argument(argument, "firewall_add")?;
    let mut manager = manager.blocking_lock();
    let config = manager.get_hot_firewall_config();
    let chain_name = resolve_chain_name(payload.chain, &config)?;
    let action = map_target_to_action(payload.target)?;
    let proto = value_if_specified(&payload.protocol).map(|p| p.to_ascii_lowercase());
    let (sport, dport) = parse_ports_from_options(&payload.options)?;

    if (sport.is_some() || dport.is_some()) && proto.is_none() {
        return Err("firewall_add: specifying ports requires Protocol".to_string());
    }

    let mut statements = Vec::new();
    if let Some(proto) = proto.clone() {
        statements.push(l4proto_match(&proto));
    }
    if let Some(in_iface) = value_if_specified(&payload.in_field) {
        statements.push(interface_match(MetaKey::Iifname, in_iface));
    }
    if let Some(out_iface) = value_if_specified(&payload.out_field) {
        statements.push(interface_match(MetaKey::Oifname, out_iface));
    }
    if let Some(src) = value_if_specified(&payload.source) {
        statements.push(address_match("saddr", src));
    }
    if let Some(dst) = value_if_specified(&payload.destination) {
        statements.push(address_match("daddr", dst));
    }
    if let Some(port) = sport {
        let proto = proto.as_deref().unwrap();
        statements.push(port_match("sport", port, proto));
    }
    if let Some(port) = dport {
        let proto = proto.as_deref().unwrap();
        statements.push(port_match("dport", port, proto));
    }
    statements.push(map_action_to_statement(action));

    let mut ruleset = manager.ruleset().clone();
    ruleset.objects.to_mut().push(schema::NfObject::ListObject(schema::NfListObject::Rule(
        build_rule(&config, &chain_name, statements),
    )));

    *manager = RulesetManager::from_ruleset(config, ruleset);
    persist_and_apply(&mut manager)?;
    Ok(format!("firewall_add: added rule to {}", payload.chain.as_str()))
}

fn firewall_delete(argument: &str, manager: &Arc<Mutex<RulesetManager>>) -> Result<String, String> {
    let payload: FirewallDeleteArg = parse_firewall_argument(argument, "firewall_delete")?;
    if payload.rule_id <= 0 {
        return Err("firewall_delete requires RuleId greater than 0".to_string());
    }

    let mut manager = manager.blocking_lock();
    let config = manager.get_hot_firewall_config();
    let chain_name = resolve_chain_name(payload.chain, &config)?;

    let mut counter = 0usize;
    let mut matched_pos = None;
    for (pos, object) in manager.ruleset().objects.iter().enumerate() {
        let schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) = object else {
            continue;
        };
        if rule.chain.as_ref() != chain_name {
            continue;
        }
        let parsed = parse_firewalld_rule(rule);
        if !matches!(parsed.target.as_str(), "ACCEPT" | "DROP") {
            continue;
        }
        counter += 1;
        if counter == payload.rule_id as usize {
            matched_pos = Some(pos);
            break;
        }
    }

    let pos = matched_pos.ok_or_else(|| {
        format!(
            "firewall_delete: RuleId {} not found in chain {}",
            payload.rule_id,
            payload.chain.as_str()
        )
    })?;

    let mut ruleset = manager.ruleset().clone();
    ruleset.objects.to_mut().remove(pos);
    *manager = RulesetManager::from_ruleset(config, ruleset);
    persist_and_apply(&mut manager)?;
    Ok(format!("firewall_delete: removed rule from {}", payload.chain.as_str()))
}

fn firewall_edit_status(
    argument: &str,
    manager: &Arc<Mutex<RulesetManager>>,
) -> Result<String, String> {
    let payload: FirewallEditStatusArg = parse_firewall_argument(argument, "firewall_edit_status")?;

    let mut manager = manager.blocking_lock();
    let mut config = manager.get_hot_firewall_config();
    let ruleset = manager.ruleset().clone();

    match payload.status {
        FirewallStatusArg::Active => {
            if !config.enabled {
                config.enabled = true;
            }
            *manager = RulesetManager::from_ruleset(config, ruleset);
            persist_and_apply(&mut manager)?;
            Ok("firewall_edit_status: firewall activated".to_string())
        }
        FirewallStatusArg::Inactive => {
            if config.enabled {
                config.enabled = false;
            }
            *manager = RulesetManager::from_ruleset(config, ruleset);
            manager.reset_table().map_err(|e| format!("firewalld reset table failed: {}", e))?;
            persist_and_apply(&mut manager)?;
            Ok("firewall_edit_status: firewall deactivated".to_string())
        }
    }
}

fn firewall_edit_policy(
    argument: &str,
    manager: &Arc<Mutex<RulesetManager>>,
) -> Result<String, String> {
    let payload: FirewallEditPolicyArg = parse_firewall_argument(argument, "firewall_edit_policy")?;

    let mut manager = manager.blocking_lock();
    let mut config = manager.get_hot_firewall_config();
    let mut ruleset = manager.ruleset().clone();

    let (chain_name, action) = match payload.chain {
        FirewallChainArg::Input => {
            config.input_policy = map_target_to_action(payload.policy)?;
            (config.input_chain.clone(), config.input_policy)
        }
        FirewallChainArg::Output => {
            config.output_policy = map_target_to_action(payload.policy)?;
            (config.output_chain.clone(), config.output_policy)
        }
    };

    let policy_value = action.into();
    for object in ruleset.objects.to_mut().iter_mut() {
        if let schema::NfObject::ListObject(schema::NfListObject::Chain(chain)) = object {
            if chain.name.as_ref() == chain_name {
                chain.policy = Some(policy_value);
            }
        }
    }

    *manager = RulesetManager::from_ruleset(config, ruleset);
    persist_and_apply(&mut manager)?;

    Ok(format!(
        "firewall_edit_policy: set {} policy to {}",
        payload.chain.as_str(),
        payload.policy.as_str()
    ))
}

fn collect_network_interfaces() -> Result<NetworkInterfacesDto, String> {
    let mut networks = BTreeMap::new();
    for interface in interfaces() {
        networks.insert(interface.name.clone(), build_network_interface_dto(&interface));
    }

    Ok(NetworkInterfacesDto { length: networks.len(), networks })
}

fn build_network_interface_dto(interface: &NetworkInterface) -> NetworkInterfaceDto {
    let (ipv4, netmask, broadcast) = extract_ipv4_details(interface);
    let mac = interface.mac.map(|mac| mac.to_string()).unwrap_or_default();
    let mtu = read_interface_mtu(&interface.name);

    NetworkInterfaceDto {
        name: interface.name.clone(),
        iface_type: classify_interface_type(interface),
        ipv4,
        netmask,
        mac,
        broadcast,
        mtu,
        status: interface_status(interface),
    }
}

fn extract_ipv4_details(interface: &NetworkInterface) -> (String, String, String) {
    for ip in &interface.ips {
        if let IpNetwork::V4(v4) = ip {
            return (v4.ip().to_string(), v4.mask().to_string(), v4.broadcast().to_string());
        }
    }
    (String::new(), String::new(), String::new())
}

fn classify_interface_type(interface: &NetworkInterface) -> String {
    let name = interface.name.to_lowercase();
    if interface.is_loopback()
        || name.starts_with("veth")
        || name.starts_with("vir")
        || name.starts_with("br")
        || name.starts_with("docker")
        || name.contains("tun")
        || name.contains("tap")
        || name.starts_with("lo")
    {
        "Virtual".to_string()
    } else {
        "Physical".to_string()
    }
}

fn interface_status(interface: &NetworkInterface) -> String {
    if interface.is_up() {
        "Up".to_string()
    } else {
        "Down".to_string()
    }
}

fn read_interface_mtu(name: &str) -> u32 {
    let path = format!("/sys/class/net/{}/mtu", name);
    fs::read_to_string(path)
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn decode_directory_argument(encoded: &str) -> Result<String, String> {
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("invalid directory argument encoding: {}", e))?;
    let dto: DirectoryArgumentDto = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid directory argument payload: {}", e))?;
    let directory = dto.directory.unwrap_or_else(|| "/".to_string());
    let normalized = directory.trim();
    if normalized.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(normalized.to_string())
    }
}

fn collect_parent_directory(directory: &str) -> Result<ParentDirectoryDto, String> {
    let target = if directory.trim().is_empty() { "/" } else { directory.trim() };

    let path = Path::new(target);
    let metadata = fs::metadata(path).map_err(|e| format!("failed to access {}: {}", target, e))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", target));
    }

    let mut files = BTreeMap::new();
    let entries =
        fs::read_dir(path).map_err(|e| format!("failed to read directory {}: {}", target, e))?;

    for entry in entries {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().into_owned();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };

        let (size, unit) = human_readable_size(metadata.len());
        let owner = format_owner(metadata.uid());
        let mode = format_mode(metadata.mode(), &file_type);
        let modified = format_modified_time(&metadata);

        files.insert(name, DirectoryEntryDto { size, unit, owner, mode, modified });
    }

    Ok(ParentDirectoryDto { length: files.len(), files })
}

fn human_readable_size(size: u64) -> (f64, String) {
    const UNITS: [(&str, f64); 4] =
        [("GB", 1024.0 * 1024.0 * 1024.0), ("MB", 1024.0 * 1024.0), ("KB", 1024.0), ("B", 1.0)];

    let size_value = size as f64;
    for (unit, divisor) in UNITS.iter() {
        if size_value >= *divisor || *unit == "B" {
            let value = if *divisor == 0.0 {
                0.0
            } else {
                ((size_value / divisor) * 100.0).round() / 100.0
            };
            return (value, (*unit).to_string());
        }
    }

    (0.0, "B".to_string())
}

fn format_owner(uid: u32) -> String {
    get_user_by_uid(uid)
        .map(|user| user.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| uid.to_string())
}

fn format_mode(mode: u32, file_type: &fs::FileType) -> String {
    fn perms(bits: u32) -> [char; 3] {
        [
            if bits & 0o4 != 0 { 'r' } else { '-' },
            if bits & 0o2 != 0 { 'w' } else { '-' },
            if bits & 0o1 != 0 { 'x' } else { '-' },
        ]
    }

    let mut result = String::with_capacity(10);
    result.push(file_type_char(file_type));

    let permissions = mode & 0o777;
    let mut user = perms((permissions >> 6) & 0o7);
    let mut group = perms((permissions >> 3) & 0o7);
    let mut other = perms(permissions & 0o7);

    if mode & 0o4000 != 0 {
        user[2] = if user[2] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        group[2] = if group[2] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        other[2] = if other[2] == 'x' { 't' } else { 'T' };
    }

    for ch in user.into_iter().chain(group).chain(other) {
        result.push(ch);
    }

    result
}

fn file_type_char(file_type: &fs::FileType) -> char {
    if file_type.is_dir() {
        'd'
    } else if file_type.is_symlink() {
        'l'
    } else if file_type.is_block_device() {
        'b'
    } else if file_type.is_char_device() {
        'c'
    } else if file_type.is_fifo() {
        'p'
    } else if file_type.is_socket() {
        's'
    } else {
        '-'
    }
}

fn format_modified_time(metadata: &fs::Metadata) -> String {
    match metadata.modified() {
        Ok(time) => {
            let datetime: DateTime<Local> = DateTime::from(time);
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Err(_) => String::new(),
    }
}

fn collect_software_inventory() -> Result<SoftwareInventoryDto, String> {
    if let Some(dto) = collect_dpkg_packages()? {
        return Ok(dto);
    }

    if let Some(dto) = collect_rpm_packages()? {
        return Ok(dto);
    }

    Err("no supported package manager detected".to_string())
}

fn collect_dpkg_packages() -> Result<Option<SoftwareInventoryDto>, String> {
    let output = match Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\t${Version}\t${db:Status-Status}\n"])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!("failed to execute dpkg-query: {}", e));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "dpkg-query exited with status {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages = BTreeMap::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(3, '\t');
        let name = parts.next().unwrap_or("").trim();
        let version = parts.next().unwrap_or("").trim();
        let status_raw = parts.next().unwrap_or("").trim().to_lowercase();

        if name.is_empty() {
            continue;
        }

        let status = if status_raw == "installed" { "Installed" } else { "Notinstall" };

        packages.insert(
            name.to_string(),
            SoftwarePackageDto { version: version.to_string(), status: status.to_string() },
        );
    }

    Ok(Some(SoftwareInventoryDto { packages }))
}

fn collect_rpm_packages() -> Result<Option<SoftwareInventoryDto>, String> {
    let output = match Command::new("rpm")
        .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\\n"])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!("failed to execute rpm: {}", e));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "rpm exited with status {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(Some(SoftwareInventoryDto { packages: BTreeMap::new() }));
    }

    let mut packages = BTreeMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, '\t');
        let name = parts.next().unwrap_or("").trim();
        let version = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }

        packages.insert(
            name.to_string(),
            SoftwarePackageDto { version: version.to_string(), status: "Installed".to_string() },
        );
    }

    Ok(Some(SoftwareInventoryDto { packages }))
}

fn collect_route_table() -> Result<RouteTableDto, String> {
    match Command::new("ip").args(["-j", "route", "show"]).output() {
        Err(e) => Err(format!("failed to execute ip route: {}", e)),
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "ip route exited with status {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ))
        }
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let entries: Vec<IpRouteJsonEntry> = serde_json::from_str(&stdout)
                .map_err(|e| format!("failed to parse ip route json: {}", e))?;

            let mut routes = BTreeMap::new();
            for entry in entries {
                let destination = entry.dst.unwrap_or_else(|| "default".to_string());
                let route = RouteEntryDto {
                    destination: destination.clone(),
                    via:         entry.gateway.unwrap_or_default(),
                    dev:         entry.dev.unwrap_or_default(),
                    proto:       entry.protocol.unwrap_or_default(),
                    metric:      entry.metric.unwrap_or(0) as i32,
                    scope:       entry.scope.unwrap_or_default(),
                    src:         entry.prefsrc.unwrap_or_default(),
                };
                routes.insert(destination, route);
            }

            Ok(RouteTableDto { length: routes.len(), routes })
        }
    }
}

fn collect_log_entries(filter: Option<(LogSearchField, String)>) -> Result<LogsDto, String> {
    let file = open_syslog_file().map_err(|e| format!("failed to open syslog: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut entries: VecDeque<LogEntryDto> = VecDeque::with_capacity(LOG_ENTRY_LIMIT);

    let mut buffer = String::new();
    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = buffer.trim_end_matches(['\n', '\r']);
                let entry =
                    parse_syslog_line(line).or_else(|| Some(build_fallback_log_entry(line)));
                if let Some(entry) = entry {
                    if matches_log_filter(&entry, filter.as_ref()) {
                        if entries.len() == LOG_ENTRY_LIMIT {
                            entries.pop_front();
                        }
                        entries.push_back(entry);
                    }
                }
            }
            Err(e) => {
                return Err(format!("failed to read syslog: {}", e));
            }
        }
    }

    let mut logs = BTreeMap::new();
    for (idx, entry) in entries.into_iter().enumerate() {
        logs.insert(format!("Log{}", idx + 1), entry);
    }

    Ok(LogsDto { length: logs.len(), logs })
}

fn open_syslog_file() -> Result<fs::File, io::Error> {
    for path in SYSLOG_CANDIDATES {
        if let Ok(file) = fs::File::open(path) {
            return Ok(file);
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no syslog file available in known locations"))
}

fn decode_log_query_argument(encoded: &str) -> Result<LogQueryDto, String> {
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("invalid log query argument encoding: {}", e))?;
    let mut dto: LogQueryDto = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid log query argument payload: {}", e))?;
    dto.parameter = dto.parameter.trim().to_string();
    Ok(dto)
}

fn matches_log_filter(entry: &LogEntryDto, filter: Option<&(LogSearchField, String)>) -> bool {
    let Some((field, raw)) = filter else {
        return true;
    };

    if raw.is_empty() {
        return true;
    }

    match field {
        LogSearchField::Month => entry.month.eq_ignore_ascii_case(raw),
        LogSearchField::Day => raw.parse::<i32>().map(|value| entry.day == value).unwrap_or(false),
        LogSearchField::Time => entry.time.starts_with(raw),
        LogSearchField::Hostname => entry.hostname.eq_ignore_ascii_case(raw),
        LogSearchField::Type => entry.r#type.eq_ignore_ascii_case(raw),
    }
}

fn parse_syslog_line(line: &str) -> Option<LogEntryDto> {
    parse_traditional_syslog_line(line).or_else(|| parse_iso_syslog_line(line))
}

fn parse_traditional_syslog_line(line: &str) -> Option<LogEntryDto> {
    fn next_token(line: &str, mut idx: usize) -> Option<(&str, usize)> {
        let bytes = line.as_bytes();
        let len = bytes.len();
        while idx < len && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= len {
            return None;
        }
        let start = idx;
        while idx < len && !bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        Some((&line[start..idx], idx))
    }

    let mut idx = 0;
    let (month, next_idx) = next_token(line, idx)?;
    idx = next_idx;
    let (day_str, next_idx) = next_token(line, idx)?;
    idx = next_idx;
    let (time, next_idx) = next_token(line, idx)?;
    idx = next_idx;
    let (hostname, next_idx) = next_token(line, idx)?;
    idx = next_idx;

    let day = day_str.parse::<i32>().ok()?;
    let rest = line.get(idx..)?.trim_start();
    if rest.is_empty() {
        return None;
    }

    let (log_type, messages) = split_type_and_message(rest);

    Some(LogEntryDto {
        month: month.to_string(),
        day,
        time: time.to_string(),
        hostname: hostname.to_string(),
        r#type: log_type,
        messages,
    })
}

fn parse_iso_syslog_line(line: &str) -> Option<LogEntryDto> {
    let mut parts = line.splitn(3, ' ');
    let timestamp = parts.next()?;
    let hostname = parts.next()?;
    let rest = parts.next().unwrap_or("").trim_start();

    let datetime = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let month = datetime.format("%b").to_string();
    let day = datetime.day() as i32;
    let time = datetime.format("%H:%M:%S").to_string();

    let (log_type, messages) = split_type_and_message(rest);

    Some(LogEntryDto {
        month,
        day,
        time,
        hostname: hostname.to_string(),
        r#type: log_type,
        messages,
    })
}

fn split_type_and_message(rest: &str) -> (String, String) {
    if let Some(pos) = rest.find(':') {
        let log_type = rest[..pos].trim().to_string();
        let messages = rest[pos + 1..].trim().to_string();
        (log_type, messages)
    } else {
        (rest.to_string(), String::new())
    }
}

fn build_fallback_log_entry(line: &str) -> LogEntryDto {
    LogEntryDto {
        month:    String::new(),
        day:      0,
        time:     String::new(),
        hostname: String::new(),
        r#type:   "raw".to_string(),
        messages: line.trim().to_string(),
    }
}

fn firewalld_status(firewalld: &Arc<Mutex<RulesetManager>>) -> Result<FirewallStatusDto, String> {
    let mut manager = firewalld.blocking_lock();
    let config = manager.get_hot_firewall_config();

    manager.ensure_basic_firewall();
    if config.enabled {
        manager.apply_only_own_table().map_err(|e| format!("firewalld apply failed: {}", e))?;
        let (config_path, ruleset_path) = firewalld_paths();
        let mut cfg = FirewalldConfig::load(config_path.as_path())
            .unwrap_or_else(|_| FirewalldConfig::default());
        cfg.save(config_path.as_path(), manager.get_hot_firewall_config())
            .map_err(|e| format!("firewalld save config failed: {}", e))?;
        manager
            .save_json(ruleset_path.as_path())
            .map_err(|e| format!("firewalld save ruleset failed: {}", e))?;
    }

    let chains = vec![
        build_firewalld_chain(
            "INPUT",
            &config.input_chain,
            config.input_policy.to_string(),
            &manager,
        ),
        build_firewalld_chain(
            "OUTPUT",
            &config.output_chain,
            config.output_policy.to_string(),
            &manager,
        ),
    ];

    let status = if config.enabled { "active" } else { "inactive" };
    Ok(FirewallStatusDto { status: status.to_string(), chains })
}

fn build_firewalld_chain(
    display_name: &str,
    actual_chain: &str,
    policy: String,
    manager: &RulesetManager,
) -> FirewallChainDto {
    let rules = collect_firewalld_rules(actual_chain, manager);
    FirewallChainDto { name: display_name.to_string(), policy, rules_length: rules.len(), rules }
}

fn collect_firewalld_rules(chain_name: &str, manager: &RulesetManager) -> Vec<FirewallRuleDto> {
    let mut collected = Vec::new();
    for object in manager.ruleset().objects.iter() {
        let schema::NfObject::ListObject(schema::NfListObject::Rule(rule)) = object else {
            continue;
        };
        if rule.chain.as_ref() != chain_name {
            continue;
        }
        let parsed = parse_firewalld_rule(rule);
        if !matches!(parsed.target.as_str(), "ACCEPT" | "DROP") {
            continue;
        }
        collected.push(FirewallRuleDto {
            id:            collected.len().saturating_add(1).to_string(),
            target:        parsed.target,
            protocol:      parsed.protocol,
            in_interface:  parsed.in_iface,
            out_interface: parsed.out_iface,
            source:        parsed.src,
            destination:   parsed.dst,
            options:       parsed.options,
        });
    }
    collected
}

struct ParsedRule {
    target:    String,
    protocol:  String,
    in_iface:  String,
    out_iface: String,
    src:       String,
    dst:       String,
    options:   String,
}

fn parse_firewalld_rule(rule: &schema::Rule<'_>) -> ParsedRule {
    let mut protocol = String::new();
    let mut in_iface = String::new();
    let mut out_iface = String::new();
    let mut src = String::new();
    let mut dst = String::new();
    let mut extras = Vec::new();
    let mut target = String::from("UNKNOWN");

    for stmt in rule.expr.iter() {
        match stmt {
            Statement::Accept(_) => target = "ACCEPT".to_string(),
            Statement::Drop(_) => target = "DROP".to_string(),
            Statement::Match(Match { left, right, .. }) => match left {
                Expression::Named(NamedExpression::Meta(Meta { key, .. })) => match key {
                    MetaKey::L4proto => protocol = expr_to_string(right),
                    MetaKey::Iifname => in_iface = expr_to_string(right),
                    MetaKey::Oifname => out_iface = expr_to_string(right),
                    _ => extras.push(expr_to_string(right)),
                },
                Expression::Named(NamedExpression::Payload(Payload::PayloadField(field))) => {
                    match field.field.as_ref() {
                        "saddr" => src = expr_to_string(right),
                        "daddr" => dst = expr_to_string(right),
                        "sport" => extras.push(format!("sport={}", expr_to_string(right))),
                        "dport" => extras.push(format!("dport={}", expr_to_string(right))),
                        _ => extras.push(expr_to_string(right)),
                    }
                }
                Expression::Named(NamedExpression::Prefix(Prefix { addr, len })) => {
                    extras.push(format!("{}/{}", expr_to_string(addr), len));
                }
                Expression::Named(NamedExpression::CT(_)) => {
                    extras.push(format!("ct={}", expr_to_string(right)));
                }
                other => extras.push(expr_to_string(other)),
            },
            _ => {}
        }
    }

    if let Some(comment) = rule.comment.as_deref() {
        extras.push(format!("comment={}", comment));
    }

    ParsedRule {
        target,
        protocol: if protocol.is_empty() { "*".to_string() } else { protocol },
        in_iface: if in_iface.is_empty() { "*".to_string() } else { in_iface },
        out_iface: if out_iface.is_empty() { "*".to_string() } else { out_iface },
        src: if src.is_empty() { "*".to_string() } else { src },
        dst: if dst.is_empty() { "*".to_string() } else { dst },
        options: extras.join(" "),
    }
}

fn expr_to_string(expr: &Expression<'_>) -> String {
    match expr {
        Expression::String(value) => value.to_string(),
        Expression::Number(value) => value.to_string(),
        Expression::List(values) => values.iter().map(expr_to_string).collect::<Vec<_>>().join(","),
        Expression::Named(NamedExpression::Prefix(Prefix { addr, len })) => {
            format!("{}/{}", expr_to_string(addr), len)
        }
        other => format!("{other:?}"),
    }
}

fn firewalld_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    (
        std::path::PathBuf::from(FIREWALLD_CONFIG_PATH),
        std::path::PathBuf::from(FIREWALLD_RULESET_PATH),
    )
}

pub async fn init_firewalld_manager() -> Result<Arc<Mutex<RulesetManager>>, String> {
    let (config_path, ruleset_path) = firewalld_paths();
    let mut app_config =
        FirewalldConfig::load(config_path.as_path()).unwrap_or_else(|_| FirewalldConfig::default());
    let base_config: BasicFirewallConfig = app_config.get_firewall_config();
    let mut manager = if ruleset_path.exists() {
        RulesetManager::from_json_file(base_config.clone(), ruleset_path.as_path())
            .map_err(|e| format!("load firewalld ruleset: {}", e))?
    } else {
        RulesetManager::new(base_config.clone())
    };
    manager.ensure_basic_firewall();
    if manager.get_hot_firewall_config().enabled {
        manager
            .apply_only_own_table()
            .map_err(|e| format!("apply initial firewalld ruleset: {}", e))?;
    }
    app_config
        .save(config_path.as_path(), manager.get_hot_firewall_config())
        .map_err(|e| format!("write firewalld config: {}", e))?;
    manager
        .save_json(ruleset_path.as_path())
        .map_err(|e| format!("persist firewalld ruleset: {}", e))?;
    Ok(Arc::new(Mutex::new(manager)))
}

fn parse_firewall_argument<T: for<'de> Deserialize<'de>>(
    encoded: &str,
    op: &str,
) -> Result<T, String> {
    let bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("{op}: invalid argument encoding: {e}"))?;
    serde_json::from_slice::<T>(&bytes).map_err(|e| format!("{op}: invalid argument payload: {e}"))
}

fn value_if_specified(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" {
        None
    } else {
        Some(trimmed)
    }
}

fn resolve_chain_name(
    chain: FirewallChainArg,
    config: &BasicFirewallConfig,
) -> Result<String, String> {
    match chain {
        FirewallChainArg::Input => Ok(config.input_chain.clone()),
        FirewallChainArg::Output => Ok(config.output_chain.clone()),
    }
}

fn map_target_to_action(target: FirewallTargetArg) -> Result<RuleAction, String> {
    match target {
        FirewallTargetArg::Accept => Ok(RuleAction::Accept),
        FirewallTargetArg::Drop => Ok(RuleAction::Drop),
    }
}

fn parse_ports_from_options(options: &str) -> Result<(Option<u16>, Option<u16>), String> {
    let mut sport = None;
    let mut dport = None;
    let mut tokens = options.split_whitespace().peekable();

    while let Some(token) = tokens.next() {
        match token {
            "--sport" | "-sport" => {
                let val = tokens
                    .next()
                    .ok_or_else(|| "firewall_add: --sport requires a value".to_string())?;
                sport = Some(parse_port_value(val)?);
            }
            "--dport" | "-dport" => {
                let val = tokens
                    .next()
                    .ok_or_else(|| "firewall_add: --dport requires a value".to_string())?;
                dport = Some(parse_port_value(val)?);
            }
            opt if opt.starts_with("--sport=") || opt.starts_with("sport=") => {
                let (_, val) = opt
                    .split_once('=')
                    .ok_or_else(|| format!("firewall_add: malformed sport option '{opt}'"))?;
                sport = Some(parse_port_value(val)?);
            }
            opt if opt.starts_with("--dport=") || opt.starts_with("dport=") => {
                let (_, val) = opt
                    .split_once('=')
                    .ok_or_else(|| format!("firewall_add: malformed dport option '{opt}'"))?;
                dport = Some(parse_port_value(val)?);
            }
            opt => {
                return Err(format!(
                    "firewall_add: unsupported option '{}' in firewalld mode",
                    opt
                ));
            }
        }
    }

    Ok((sport, dport))
}

fn parse_port_value(value: &str) -> Result<u16, String> {
    value.parse::<u16>().map_err(|e| format!("firewall_add: invalid port '{}': {}", value, e))
}

fn l4proto_match(proto: &str) -> Statement<'static> {
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::L4proto })),
        right: Expression::String(Cow::Owned(proto.to_ascii_lowercase())),
        op:    nftables::stmt::Operator::EQ,
    })
}

fn interface_match(key: MetaKey, iface: &str) -> Statement<'static> {
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Meta(Meta { key })),
        right: Expression::String(Cow::Owned(iface.to_string())),
        op:    nftables::stmt::Operator::EQ,
    })
}

fn address_match(field: &'static str, value: &str) -> Statement<'static> {
    let protocol = if value.contains(':') { Cow::Borrowed("ip6") } else { Cow::Borrowed("ip") };
    let expr = if let Some((addr, prefix_len)) = value.split_once('/') {
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
            len:  prefix_len.parse().unwrap_or(0),
        }))
    } else {
        Expression::String(Cow::Owned(value.to_string()))
    };
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            nftables::expr::PayloadField { protocol, field: Cow::Borrowed(field) },
        ))),
        right: expr,
        op:    nftables::stmt::Operator::EQ,
    })
}

fn port_match(field: &'static str, port: u16, proto: &str) -> Statement<'static> {
    Statement::Match(Match {
        left:  Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            nftables::expr::PayloadField {
                protocol: Cow::Owned(proto.to_ascii_lowercase()),
                field:    Cow::Borrowed(field),
            },
        ))),
        right: Expression::Number(port as u32),
        op:    nftables::stmt::Operator::EQ,
    })
}

fn map_action_to_statement(action: RuleAction) -> Statement<'static> {
    match action {
        RuleAction::Accept => Statement::Accept(Some(nftables::stmt::Accept {})),
        RuleAction::Drop => Statement::Drop(Some(nftables::stmt::Drop {})),
    }
}

fn build_rule(
    config: &BasicFirewallConfig,
    chain_name: &str,
    statements: Vec<Statement<'static>>,
) -> schema::Rule<'static> {
    schema::Rule {
        family: config.family,
        table: Cow::Owned(config.table.clone()),
        chain: Cow::Owned(chain_name.to_string()),
        expr: statements.into(),
        comment: None,
        ..Default::default()
    }
}

fn persist_and_apply(manager: &mut RulesetManager) -> Result<(), String> {
    manager.ensure_basic_firewall();
    let (config_path, ruleset_path) = firewalld_paths();

    if manager.get_hot_firewall_config().enabled {
        manager.apply_only_own_table().map_err(|e| format!("apply firewalld ruleset: {}", e))?;
    }

    let mut app_config =
        FirewalldConfig::load(config_path.as_path()).unwrap_or_else(|_| FirewalldConfig::default());
    app_config
        .save(config_path.as_path(), manager.get_hot_firewall_config())
        .map_err(|e| format!("write firewalld config: {}", e))?;
    manager
        .save_json(ruleset_path.as_path())
        .map_err(|e| format!("persist firewalld ruleset: {}", e))?;

    Ok(())
}

fn collect_dns_info() -> Result<DnsInfoDto, String> {
    let hostname = fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();

    let file = fs::File::open("/etc/resolv.conf")
        .map_err(|e| format!("failed to open resolv.conf: {}", e))?;
    let reader = io::BufReader::new(file);

    let mut nameservers = Vec::new();
    for line in reader.lines() {
        if let Ok(line) = line {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    nameservers.push(parts[1].to_string());
                }
            }
        }
        if nameservers.len() >= 2 {
            break;
        }
    }

    let primary = nameservers.first().cloned().unwrap_or_default();
    let secondary = nameservers.get(1).cloned().unwrap_or_default();

    Ok(DnsInfoDto { hostname, dns: DnsServersDto { primary, secondary } })
}

fn collect_process_info(sys: &mut System) -> Result<ProcessInfoDto, String> {
    match collect_systemd_processes() {
        Ok(dto) => Ok(dto),
        Err(_) => collect_fallback_processes(sys),
    }
}

fn collect_systemd_processes() -> Result<ProcessInfoDto, String> {
    let mut enabled_map = BTreeMap::new();
    let enabled = Command::new("systemctl")
        .args(["list-unit-files", "--type=service", "--no-legend", "--no-pager"])
        .output()
        .map_err(|e| format!("failed to run systemctl list-unit-files: {}", e))?;

    if !enabled.status.success() {
        let stderr = String::from_utf8_lossy(&enabled.stderr).trim().to_string();
        return Err(format!("systemctl list-unit-files failed: {}", stderr));
    }

    for line in String::from_utf8_lossy(&enabled.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if let (Some(unit), Some(state)) = (parts.next(), parts.next()) {
            enabled_map.insert(unit.to_string(), state.to_string());
        }
    }

    let mut active_map = BTreeMap::new();
    let active = Command::new("systemctl")
        .args(["list-units", "--type=service", "--no-legend", "--no-pager", "--all"])
        .output()
        .map_err(|e| format!("failed to run systemctl list-units: {}", e))?;

    if !active.status.success() {
        let stderr = String::from_utf8_lossy(&active.stderr).trim().to_string();
        return Err(format!("systemctl list-units failed: {}", stderr));
    }

    for line in String::from_utf8_lossy(&active.stdout).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if let (Some(unit), Some(_load), Some(active_state)) =
            (parts.next(), parts.next(), parts.next())
        {
            active_map.insert(unit.to_string(), active_state.to_string());
        }
    }

    if enabled_map.is_empty() && active_map.is_empty() {
        return Err("systemctl returned no process entries".to_string());
    }

    let mut names: BTreeSet<String> = enabled_map.keys().cloned().collect();
    names.extend(active_map.keys().cloned());

    let mut entries = Vec::new();
    for unit in names {
        let enabled_state = enabled_map.get(&unit).map(|s| s.as_str()).unwrap_or("");
        let active_state = active_map.get(&unit).map(|s| s.as_str()).unwrap_or("");

        let name = unit.strip_suffix(".service").unwrap_or(&unit).to_string();
        let status = matches!(active_state, "active" | "activating" | "reloading");
        let boot =
            matches!(enabled_state, "enabled" | "enabled-runtime" | "linked" | "linked-runtime");

        entries.push(ProcessEntryDto { name, status: ProcessStatusDto { status, boot } });
    }

    Ok(ProcessInfoDto { length: entries.len(), entries })
}

fn collect_fallback_processes(sys: &mut System) -> Result<ProcessInfoDto, String> {
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );
    let processes = sys
        .processes()
        .values()
        .map(|process| {
            let name = process.name().to_string_lossy().to_string();
            let status = matches!(process.status(), ProcessStatus::Run | ProcessStatus::Idle);
            let boot = true;
            ProcessEntryDto { name, status: ProcessStatusDto { status, boot } }
        })
        .collect::<Vec<ProcessEntryDto>>();

    Ok(ProcessInfoDto { length: processes.len(), entries: processes })
}

fn serialize_cron_jobs() -> Result<String, io::Error> {
    let mut jobs = Vec::new();
    collect_cron_jobs(&mut jobs)?;
    let length = jobs.len();

    serde_json::to_string(&CronJobsDto { jobs, length }).map_err(io::Error::other)
}

fn collect_cron_jobs(target: &mut Vec<CronJobDto>) -> Result<(), io::Error> {
    parse_cron_file(Path::new("/etc/crontab"), None, target)?;
    parse_cron_directory(Path::new("/etc/cron.d"), target)?;
    parse_user_cron_directory(Path::new("/var/spool/cron"), target)?;
    parse_user_cron_directory(Path::new("/var/spool/cron/crontabs"), target)?;
    Ok(())
}

fn parse_cron_directory(dir: &Path, target: &mut Vec<CronJobDto>) -> Result<(), io::Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {
            return Ok(())
        }
        Err(e) => return Err(e),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            match parse_cron_file(&path, None, target) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn parse_user_cron_directory(dir: &Path, target: &mut Vec<CronJobDto>) -> Result<(), io::Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {
            return Ok(())
        }
        Err(e) => return Err(e),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(user) = path.file_name().and_then(|n| n.to_str()) {
                match parse_cron_file(&path, Some(user), target) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}

fn parse_cron_file(
    path: &Path,
    default_user: Option<&str>,
    target: &mut Vec<CronJobDto>,
) -> Result<(), io::Error> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {
            return Ok(())
        }
        Err(e) => return Err(e),
    };

    let reader = io::BufReader::new(file);
    for (idx, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(e) => return Err(e),
        };
        if let Some(job) = parse_cron_line(&line, default_user, path, idx + 1) {
            target.push(job);
        }
    }
    Ok(())
}

fn parse_cron_line(
    line: &str,
    default_user: Option<&str>,
    path: &Path,
    line_no: usize,
) -> Option<CronJobDto> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('@') {
        return None;
    }

    if trimmed.starts_with('#') {
        // Ignore pure comment lines.
        return None;
    }

    let mut body = trimmed;
    let mut meta: Option<CronMeta> = None;

    if let Some(idx) = trimmed.find(META_PREFIX) {
        let meta_str = &trimmed[idx + META_PREFIX.len()..];
        if let Ok(parsed) = serde_json::from_str::<CronMeta>(meta_str.trim()) {
            meta = Some(parsed);
        }
        body = trimmed[..idx].trim_end();
    }

    let tokens: Vec<&str> = body.split_whitespace().collect();
    if tokens.len() < 5 {
        return None;
    }

    let (minute, hour, date, month, week) = (tokens[0], tokens[1], tokens[2], tokens[3], tokens[4]);
    let (username, command_start) = if let Some(user) = default_user {
        if tokens.len() < 6 {
            return None;
        }
        (user.to_string(), 5)
    } else {
        if tokens.len() < 7 {
            return None;
        }
        (tokens[5].to_string(), 6)
    };

    let command_tokens = &tokens[command_start..];
    if command_tokens.is_empty() {
        return None;
    }

    let command = command_tokens.join(" ");

    let schedule = CronScheduleDto {
        minute: parse_cron_field(minute),
        hour:   parse_cron_field(hour),
        date:   parse_cron_field(date),
        month:  parse_cron_field(month),
        week:   parse_cron_field(week),
    };

    let (id, name) = if let Some(meta) = meta {
        (meta.id, meta.name)
    } else {
        let generated_id = format!("sys:{}:{}", path.display(), line_no);
        let default_name = format!("{}:{}", path.display(), line_no);
        (generated_id, default_name)
    };

    Some(CronJobDto { id, name, command, schedule, username })
}

fn parse_cron_field(field: &str) -> i32 {
    if field == "*" {
        -1
    } else {
        field.parse::<i32>().unwrap_or(-1)
    }
}
