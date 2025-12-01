use std::{convert::TryFrom, io, str::FromStr};

use chrono::{Datelike, NaiveDate, Weekday};
use serde::Deserialize;

use crate::{
    execute_host_body, last_non_empty_line, make_sysinfo_command, send_to_hostd, shell_quote,
    SystemInfo,
};

const ERROR_LOG_LINE_LIMIT: usize = 50;
const ACCESS_LOG_LINE_LIMIT: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApacheStatus {
    Active,
    Stopped,
    Uninstalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Active,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct ServerHostInfo {
    pub hostname: String,
    pub status:   ServerStatus,
    pub cpu:      f64,
    pub memory:   f64,
    pub ip:       String,
}

#[derive(Debug, Clone, Copy)]
pub enum ApacheAction {
    Start,
    Stop,
    Restart,
}

impl ApacheAction {
    fn command_name(self) -> &'static str {
        match self {
            ApacheAction::Start => "server_apache_start",
            ApacheAction::Stop => "server_apache_stop",
            ApacheAction::Restart => "server_apache_restart",
        }
    }

    fn systemctl_subcommand(self) -> &'static str {
        match self {
            ApacheAction::Start => "start",
            ApacheAction::Stop => "stop",
            ApacheAction::Restart => "restart",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApacheLogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Crit,
    Alert,
    Emerg,
}

impl ApacheLogLevel {
    fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "debug" => ApacheLogLevel::Debug,
            "info" => ApacheLogLevel::Info,
            "notice" => ApacheLogLevel::Notice,
            "warn" | "warning" => ApacheLogLevel::Warn,
            "error" => ApacheLogLevel::Error,
            "crit" | "critical" => ApacheLogLevel::Crit,
            "alert" => ApacheLogLevel::Alert,
            "emerg" | "emergency" => ApacheLogLevel::Emerg,
            _ => ApacheLogLevel::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApacheMonth {
    Jan,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
}

impl ApacheMonth {
    fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "jan" => Some(ApacheMonth::Jan),
            "feb" => Some(ApacheMonth::Feb),
            "mar" => Some(ApacheMonth::Mar),
            "apr" => Some(ApacheMonth::Apr),
            "may" => Some(ApacheMonth::May),
            "jun" => Some(ApacheMonth::Jun),
            "jul" => Some(ApacheMonth::Jul),
            "aug" => Some(ApacheMonth::Aug),
            "sep" => Some(ApacheMonth::Sep),
            "oct" => Some(ApacheMonth::Oct),
            "nov" => Some(ApacheMonth::Nov),
            "dec" => Some(ApacheMonth::Dec),
            _ => None,
        }
    }

    fn number(self) -> u32 {
        match self {
            ApacheMonth::Jan => 1,
            ApacheMonth::Feb => 2,
            ApacheMonth::Mar => 3,
            ApacheMonth::Apr => 4,
            ApacheMonth::May => 5,
            ApacheMonth::Jun => 6,
            ApacheMonth::Jul => 7,
            ApacheMonth::Aug => 8,
            ApacheMonth::Sep => 9,
            ApacheMonth::Oct => 10,
            ApacheMonth::Nov => 11,
            ApacheMonth::Dec => 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApacheWeek {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl ApacheWeek {
    fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mon" => Some(ApacheWeek::Mon),
            "tue" | "tues" | "tuesday" => Some(ApacheWeek::Tue),
            "wed" | "weds" | "wednesday" => Some(ApacheWeek::Wed),
            "thu" | "thur" | "thurs" | "thursday" => Some(ApacheWeek::Thu),
            "fri" | "friday" => Some(ApacheWeek::Fri),
            "sat" | "saturday" => Some(ApacheWeek::Sat),
            "sun" | "sunday" => Some(ApacheWeek::Sun),
            _ => None,
        }
    }

    fn from_weekday(weekday: Weekday) -> Self {
        match weekday {
            Weekday::Mon => ApacheWeek::Mon,
            Weekday::Tue => ApacheWeek::Tue,
            Weekday::Wed => ApacheWeek::Wed,
            Weekday::Thu => ApacheWeek::Thu,
            Weekday::Fri => ApacheWeek::Fri,
            Weekday::Sat => ApacheWeek::Sat,
            Weekday::Sun => ApacheWeek::Sun,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApacheTime {
    pub hour: u32,
    pub min:  u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApacheDate {
    pub year:  i32,
    pub month: ApacheMonth,
    pub day:   i32,
    pub week:  ApacheWeek,
    pub time:  ApacheTime,
}

#[derive(Debug, Clone)]
pub struct ApacheErrorLogEntry {
    pub date:    ApacheDate,
    pub module:  String,
    pub level:   ApacheLogLevel,
    pub pid:     i64,
    pub client:  String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ApacheAccessLogEntry {
    pub ip:         String,
    pub date:       ApacheDate,
    pub method:     String,
    pub url:        String,
    pub protocol:   String,
    pub status:     i64,
    pub byte:       i64,
    pub referer:    String,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct ApacheLogs {
    pub error_log:  Vec<ApacheErrorLogEntry>,
    pub errlength:  usize,
    pub access_log: Vec<ApacheAccessLogEntry>,
    pub acclength:  usize,
}

#[derive(Debug, Clone)]
pub struct ApacheServerInfo {
    pub hostname:    String,
    pub status:      ApacheStatus,
    pub cpu:         f64,
    pub memory:      f64,
    pub connections: i64,
    pub ip:          String,
    pub logs:        ApacheLogs,
}

#[derive(Debug, Clone, Copy)]
struct ApacheConfig {
    service_name: &'static str,
    process_name: &'static str,
    error_log:    &'static str,
    access_log:   &'static str,
}

impl ApacheConfig {
    fn for_system(sys: &SystemInfo) -> Self {
        match sys.os_id.as_str() {
            "centos" | "rocky" | "rhel" | "almalinux" | "scientific" | "oracle" | "fedora" => {
                Self {
                    service_name: "httpd",
                    process_name: "httpd",
                    error_log:    "/var/log/httpd/error_log",
                    access_log:   "/var/log/httpd/access_log",
                }
            }
            _ => Self {
                service_name: "apache2",
                process_name: "apache2",
                error_log:    "/var/log/apache2/error.log",
                access_log:   "/var/log/apache2/access.log",
            },
        }
    }
}

#[derive(Deserialize)]
struct ServerQueryArgument {
    #[serde(rename = "Server")]
    server: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServicePresence {
    Active,
    Inactive,
    NotFound,
}

fn round_two(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

pub async fn get_server_apache(sys: &SystemInfo) -> io::Result<ApacheServerInfo> {
    let config = ApacheConfig::for_system(sys);
    let hostname = fetch_hostname().await?;
    let ip = fetch_public_ip().await?;
    let presence = detect_service_presence(config.service_name).await;
    if matches!(presence, Ok(ServicePresence::NotFound)) {
        return Ok(ApacheServerInfo {
            hostname,
            status: ApacheStatus::Uninstalled,
            cpu: 0.0,
            memory: 0.0,
            connections: 0,
            ip,
            logs: ApacheLogs {
                error_log:  Vec::new(),
                errlength:  0,
                access_log: Vec::new(),
                acclength:  0,
            },
        });
    }
    let status = match presence {
        Ok(ServicePresence::Active) => ApacheStatus::Active,
        Ok(ServicePresence::Inactive) => ApacheStatus::Stopped,
        _ => fetch_service_status(&config).await?,
    };
    let (cpu_raw, memory_raw) = fetch_cpu_memory(&config).await?;
    let cpu = round_two(cpu_raw);
    let memory = round_two(memory_raw);
    let connections = fetch_connection_count().await?;
    let error_lines = fetch_log_lines(config.error_log, ERROR_LOG_LINE_LIMIT).await?;
    let access_lines = fetch_log_lines(config.access_log, ACCESS_LOG_LINE_LIMIT).await?;
    let error_log = parse_error_log_entries(&error_lines);
    let access_log = parse_access_log_entries(&access_lines);
    let logs = ApacheLogs {
        errlength: error_log.len(),
        acclength: access_log.len(),
        error_log,
        access_log,
    };

    Ok(ApacheServerInfo { hostname, status, cpu, memory, connections, ip, logs })
}

pub async fn get_server_install(
    argument: &str,
    sys: &SystemInfo,
) -> Result<ServerHostInfo, String> {
    let server = parse_server_argument(argument)?;
    let service = resolve_service_name(&server, sys);
    let presence = detect_service_presence(&service)
        .await
        .map_err(|e| format!("{server} query error: {e}"))?;
    match presence {
        ServicePresence::Active => collect_server_host_info(ServerStatus::Active, sys)
            .await
            .map_err(|e| format!("failed to collect host info: {e}")),
        ServicePresence::Inactive => collect_server_host_info(ServerStatus::Stopped, sys)
            .await
            .map_err(|e| format!("failed to collect host info: {e}")),
        ServicePresence::NotFound => Err(format!("{server} not installed")),
    }
}

pub async fn get_server_noninstall(
    argument: &str,
    sys: &SystemInfo,
) -> Result<ServerHostInfo, String> {
    let server = parse_server_argument(argument)?;
    let service = resolve_service_name(&server, sys);
    let presence = detect_service_presence(&service)
        .await
        .map_err(|e| format!("{server} query error: {e}"))?;
    match presence {
        ServicePresence::NotFound => collect_server_host_info(ServerStatus::Stopped, sys)
            .await
            .map_err(|e| format!("failed to collect host info: {e}")),
        ServicePresence::Active | ServicePresence::Inactive => {
            Err(format!("{server} already installed"))
        }
    }
}

fn parse_server_argument(argument: &str) -> Result<String, String> {
    let parsed: ServerQueryArgument = serde_json::from_str(argument)
        .map_err(|e| format!("server argument parse error: {}", e))?;
    let trimmed = parsed.server.trim();
    if trimmed.is_empty() {
        return Err("Server cannot be empty".to_string());
    }
    Ok(trimmed.to_string())
}

fn resolve_service_name(server: &str, sys: &SystemInfo) -> String {
    match server.to_ascii_lowercase().as_str() {
        "apache" => ApacheConfig::for_system(sys).process_name.to_string(),
        other => other.to_string(),
    }
}

async fn collect_server_host_info(
    status: ServerStatus,
    sys: &SystemInfo,
) -> io::Result<ServerHostInfo> {
    let hostname = fetch_hostname().await?;
    let config = ApacheConfig::for_system(sys);
    let (cpu_raw, memory_raw) = fetch_cpu_memory(&config).await?;
    let cpu = round_two(cpu_raw);
    let memory = round_two(memory_raw);
    let ip = fetch_public_ip().await?;
    Ok(ServerHostInfo { hostname, status, cpu, memory, ip })
}

async fn detect_service_presence(service: &str) -> io::Result<ServicePresence> {
    let svc = shell_quote(service);
    let script = format!(
        "systemctl status {svc} >/dev/null 2>&1\ncode=$?\nif [ \"$code\" -eq 4 ]; then\n  printf \
         '%s\\n' 'notfound'\n  exit 0\nfi\nstate=$(systemctl is-active {svc} 2>/dev/null || \
         true)\nprintf '%s\\n' \"$state\"\n"
    );
    let output = run_host_command(&script, "systemctl query").await?;
    let trimmed = output.trim();
    Ok(match trimmed {
        "active" => ServicePresence::Active,
        "inactive" | "failed" | "activating" | "deactivating" => ServicePresence::Inactive,
        _ => ServicePresence::NotFound,
    })
}

pub async fn execute_server_apache_action(
    action: ApacheAction,
    sys: &SystemInfo,
) -> Result<String, String> {
    let config = ApacheConfig::for_system(sys);
    let service = shell_quote(config.service_name);
    let command = format!("systemctl {} {}", action.systemctl_subcommand(), service);
    let success_message = format!("{}: {}", action.command_name(), config.service_name);
    let body = format!("{command}\nprintf '%s\\n' {}\n", shell_quote(&success_message));

    let result = execute_host_body(&body)
        .await
        .map_err(|err| format!("{} host error: {}", action.command_name(), err))?;

    if result.status == 0 {
        let message = last_non_empty_line(&result.output)
            .map(|line| line.to_string())
            .unwrap_or(success_message);
        Ok(message)
    } else if result.output.trim().is_empty() {
        Err(format!("{} failed with status {}", action.command_name(), result.status))
    } else {
        Err(result.output.trim().to_string())
    }
}

async fn fetch_hostname() -> io::Result<String> {
    let output = run_host_command("hostname\n", "hostname lookup").await?;
    Ok(output.trim().to_string())
}

async fn fetch_service_status(config: &ApacheConfig) -> io::Result<ApacheStatus> {
    let service = shell_quote(config.service_name);
    let script = format!(
        "status=$(systemctl is-active {service} 2>/dev/null || true)\nprintf '%s\\n' \"$status\"\n"
    );
    let output = run_host_command(&script, "apache service status").await?;
    let normalized = output.trim().to_ascii_lowercase();
    Ok(if normalized == "active" || normalized == "running" {
        ApacheStatus::Active
    } else {
        ApacheStatus::Stopped
    })
}

async fn fetch_cpu_memory(config: &ApacheConfig) -> io::Result<(f64, f64)> {
    let process = shell_quote(config.process_name);
    let script = format!("ps --no-headers -C {process} -o %cpu,%mem 2>/dev/null || true\n");
    let output = run_host_command(&script, "apache resource usage").await?;

    let mut total_cpu = 0.0f64;
    let mut total_mem = 0.0f64;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if let (Some(cpu_raw), Some(mem_raw)) = (parts.next(), parts.next()) {
            if let Ok(value) = cpu_raw.replace(',', ".").parse::<f64>() {
                total_cpu += value;
            }
            if let Ok(value) = mem_raw.replace(',', ".").parse::<f64>() {
                total_mem += value;
            }
        }
    }

    Ok((total_cpu, total_mem))
}

async fn fetch_connection_count() -> io::Result<i64> {
    let script = r#"
count=0
if command -v ss >/dev/null 2>&1; then
  count=$(ss -Htan state established 2>/dev/null | awk '{local=$4; if (local ~ /:80$/ || local ~ /:443$/) count++} END {print count}')
elif command -v netstat >/dev/null 2>&1; then
  count=$(netstat -tan 2>/dev/null | awk 'NR>2 {local=$4; if (local ~ /:80$/ || local ~ /:443$/) count++} END {print count}')
else
  count=0
fi
printf '%s\n' "$count"
"#;
    let output = run_host_command(script, "apache connection count").await?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed.parse::<i64>().map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid connection count: {}", err))
    })
}

async fn fetch_public_ip() -> io::Result<String> {
    if let Ok(Some(ip)) = fetch_sysinfo_local_ip().await {
        return Ok(ip);
    }

    let script = r#"
ip_addr=""
if command -v ip >/dev/null 2>&1; then
  ip_addr=$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1 {for (i = 1; i <= NF; i++) if ($i == "src") {print $(i+1); exit}}')
fi
if [ -z "$ip_addr" ]; then
  if command -v hostname >/dev/null 2>&1; then
    ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
fi
printf '%s\n' "$ip_addr"
"#;
    let output = run_host_command(script, "apache public ip").await?;
    let trimmed = output.trim();
    Ok(if trimmed.is_empty() { "0.0.0.0".to_string() } else { trimmed.to_string() })
}

async fn fetch_sysinfo_local_ip() -> io::Result<Option<String>> {
    let cmd = make_sysinfo_command("local_ip");
    match send_to_hostd(&cmd).await {
        Ok(output) => {
            let trimmed = output.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(err) => Err(err),
    }
}

async fn fetch_log_lines(path: &str, limit: usize) -> io::Result<Vec<String>> {
    let log_path = shell_quote(path);
    let script =
        format!("LOG={log_path}\nif [ -f \"$LOG\" ]; then\n  tail -n {limit} \"$LOG\"\nfi\n");
    let output = run_host_command(&script, path).await?;
    Ok(output.lines().map(|line| line.to_string()).collect())
}

fn parse_error_log_entries(lines: &[String]) -> Vec<ApacheErrorLogEntry> {
    lines.iter().filter_map(|line| parse_error_log_entry(line)).collect()
}

fn parse_error_log_entry(line: &str) -> Option<ApacheErrorLogEntry> {
    let (blocks, message) = split_bracket_blocks(line)?;
    let date_block = blocks.first()?.trim();
    let date = parse_error_log_date(date_block)?;

    let mut module = "unknown".to_string();
    let mut level = ApacheLogLevel::Info;
    let mut pid = 0i64;
    let mut client = String::new();

    for block in blocks.iter().skip(1) {
        let trimmed = block.trim();
        if let Some((left, right)) = trimmed.split_once(':') {
            if matches!(module.as_str(), "unknown") {
                module = left.trim().to_string();
                level = ApacheLogLevel::from_str(right.trim());
                continue;
            }
        }

        if trimmed.starts_with("pid ") {
            if let Some(value) = trimmed.split_whitespace().nth(1) {
                let digits = value.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>();
                if let Ok(parsed) = digits.parse::<i64>() {
                    pid = parsed;
                }
            }
        } else if let Some(stripped) = trimmed.strip_prefix("client ") {
            client = stripped.trim().to_string();
        }
    }

    Some(ApacheErrorLogEntry {
        date,
        module,
        level,
        pid,
        client,
        message: message.trim().to_string(),
    })
}

fn parse_error_log_date(block: &str) -> Option<ApacheDate> {
    let mut parts = block.split_whitespace();
    let week_raw = parts.next()?;
    let month_raw = parts.next()?;
    let day_raw = parts.next()?;
    let time_raw = parts.next()?;
    let year_raw = parts.next()?;

    let week = ApacheWeek::from_str(week_raw)?;
    let month = ApacheMonth::from_str(month_raw)?;
    let day = i32::from_str(day_raw).ok()?;
    let year = i32::from_str(year_raw).ok()?;
    let (hour, min) = parse_hour_min(time_raw)?;

    Some(ApacheDate { year, month, day, week, time: ApacheTime { hour, min } })
}

fn parse_access_log_entries(lines: &[String]) -> Vec<ApacheAccessLogEntry> {
    lines.iter().filter_map(|line| parse_access_log_entry(line)).collect()
}

fn parse_access_log_entry(line: &str) -> Option<ApacheAccessLogEntry> {
    let mut segments = line.split('"');
    let prefix = segments.next().unwrap_or("").trim();
    let request = segments.next().unwrap_or("").trim();
    let status_block = segments.next().unwrap_or("").trim();
    let referer = segments.next().unwrap_or("").trim().to_string();
    let _ = segments.next();
    let user_agent = segments.next().unwrap_or("").trim().to_string();

    let ip = prefix.split_whitespace().next()?.to_string();
    let date_block = extract_bracket_content(prefix)?;
    let date = parse_access_log_date(&date_block)?;

    let mut request_parts = request.split_whitespace();
    let method = request_parts.next().unwrap_or("-").to_string();
    let url = request_parts.next().unwrap_or("-").to_string();
    let protocol = request_parts.next().unwrap_or("-").to_string();

    let mut status_parts = status_block.split_whitespace();
    let status = status_parts.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
    let bytes_raw = status_parts.next().unwrap_or("0");
    let byte = i64::from_str(bytes_raw).unwrap_or(0);

    Some(ApacheAccessLogEntry {
        ip,
        date,
        method,
        url,
        protocol,
        status,
        byte,
        referer,
        user_agent,
    })
}

fn parse_access_log_date(block: &str) -> Option<ApacheDate> {
    let mut parts = block.split_whitespace();
    let timestamp = parts.next()?;
    let mut timestamp_parts = timestamp.split(':');
    let date_part = timestamp_parts.next()?;
    let hour = timestamp_parts.next()?.parse::<u32>().ok()?;
    let min = timestamp_parts.next()?.parse::<u32>().ok()?;
    let date_components: Vec<_> = date_part.split('/').collect();
    if date_components.len() != 3 {
        return None;
    }
    let day = i32::from_str(date_components[0]).ok()?;
    let month = ApacheMonth::from_str(date_components[1])?;
    let year = i32::from_str(date_components[2]).ok()?;
    let day_u32 = u32::try_from(day).ok()?;
    let week = NaiveDate::from_ymd_opt(year, month.number(), day_u32)
        .map(|date| ApacheWeek::from_weekday(date.weekday()))?;

    Some(ApacheDate { year, month, day, week, time: ApacheTime { hour, min } })
}

fn parse_hour_min(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let min = parts.next()?.parse::<u32>().ok()?;
    Some((hour, min))
}

fn split_bracket_blocks(line: &str) -> Option<(Vec<String>, String)> {
    let mut blocks = Vec::new();
    let mut remainder = line;
    while let Some(start) = remainder.find('[') {
        let after_start = &remainder[start + 1..];
        let end = after_start.find(']')?;
        blocks.push(after_start[..end].to_string());
        remainder = &after_start[end + 1..];
        if !remainder.trim_start().starts_with('[') {
            break;
        }
    }
    Some((blocks, remainder.trim().to_string()))
}

fn extract_bracket_content(text: &str) -> Option<String> {
    let start = text.find('[')?;
    let rest = &text[start + 1..];
    let end = rest.find(']')?;
    Some(rest[..end].to_string())
}

async fn run_host_command(script: &str, context: &str) -> io::Result<String> {
    let result = execute_host_body(script)
        .await
        .map_err(|err| io::Error::other(format!("{context} host error: {err}")))?;
    if result.status != 0 {
        let output = result.output.trim();
        let message = if output.is_empty() {
            format!("{context} failed with status {}", result.status)
        } else {
            format!("{context} failed: {}", output)
        };
        return Err(io::Error::other(message));
    }
    Ok(result.output)
}
