// Functions: get_process, process_start, process_stop, process_restart,
// process_enable, process_disable, process_start_enable, process_stop_disable

use std::{collections::HashMap, io};

use crate::{
    execute_host_body, family_key, last_non_empty_line, make_sysinfo_command, send_to_hostd,
    shell_quote, SystemInfo,
};
use serde::Deserialize;
use serde_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    StartEnable,
    StopDisable,
}

impl ProcessAction {
    pub fn command_name(self) -> &'static str {
        match self {
            ProcessAction::Start => "process_start",
            ProcessAction::Stop => "process_stop",
            ProcessAction::Restart => "process_restart",
            ProcessAction::Enable => "process_enable",
            ProcessAction::Disable => "process_disable",
            ProcessAction::StartEnable => "process_start_enable",
            ProcessAction::StopDisable => "process_stop_disable",
        }
    }

    fn template(self) -> &'static str {
        match self {
            ProcessAction::Start => "systemctl start {process}",
            ProcessAction::Stop => "systemctl stop {process}",
            ProcessAction::Restart => "systemctl restart {process}",
            ProcessAction::Enable => "systemctl enable {process}",
            ProcessAction::Disable => "systemctl disable {process}",
            ProcessAction::StartEnable => "systemctl enable --now {process}",
            ProcessAction::StopDisable => "systemctl disable --now {process}",
        }
    }
}

#[derive(Debug)]
pub struct ProcessStatus {
    pub status: bool,
    pub boot:   bool,
}

#[derive(Debug)]
pub struct ProcessEntry {
    pub name:   String,
    pub status: ProcessStatus,
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub entries: Vec<ProcessEntry>,
    pub length:  usize,
}

#[derive(Deserialize)]
struct ProcessInfoDto {
    #[serde(rename = "Entries")]
    entries: Vec<ProcessEntryDto>,
    #[serde(rename = "Length")]
    _length: usize,
}

#[derive(Deserialize)]
struct ProcessEntryDto {
    #[serde(rename = "Name")]
    name:   String,
    #[serde(rename = "Status")]
    status: ProcessStatusDto,
}

#[derive(Deserialize)]
struct ProcessStatusDto {
    #[serde(rename = "Status")]
    status: bool,
    #[serde(rename = "Boot")]
    boot:   bool,
}

fn parse_process_info(output: &str) -> io::Result<ProcessInfo> {
    let dto: ProcessInfoDto = serde_json::from_str(output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse process info JSON: {}", e),
        )
    })?;

    let entries = dto
        .entries
        .into_iter()
        .map(|entry| ProcessEntry {
            name:   entry.name,
            status: ProcessStatus { status: entry.status.status, boot: entry.status.boot },
        })
        .collect::<Vec<_>>();

    Ok(ProcessInfo { length: entries.len(), entries })
}

pub async fn process_info_structured(_sys: &SystemInfo) -> io::Result<ProcessInfo> {
    let cmd = make_sysinfo_command("process_list");
    let output = send_to_hostd(&cmd).await?;
    parse_process_info(&output)
}

pub async fn execute_process_command(
    action: ProcessAction,
    argument: Option<&str>,
    sys: &SystemInfo,
) -> Result<String, String> {
    let command_name = action.command_name();
    let process = argument.ok_or_else(|| format!("{command_name} requires a process name"))?.trim();

    validate_process_name(process)?;

    let template = resolve_command_template(action, sys)
        .ok_or_else(|| format!("{command_name} unsupported on {} {}", sys.os_id, sys.version_id))?;

    let command = template.replace("{process}", process);
    let success_message = format!("{}: {}", command_name, process);

    let body = format!("{}\nprintf '%s\\n' {}\n", command, shell_quote(&success_message));

    let result = execute_host_body(&body).await?;
    if result.status == 0 {
        let message = last_non_empty_line(&result.output)
            .map(|line| line.to_string())
            .unwrap_or_else(|| success_message.clone());
        Ok(message)
    } else {
        let message = if result.output.trim().is_empty() {
            format!("{} failed with status {}", success_message, result.status)
        } else {
            result.output.trim().to_string()
        };
        Err(message)
    }
}

fn validate_process_name(process: &str) -> Result<(), String> {
    if process.is_empty() {
        return Err("process name cannot be empty".to_string());
    }

    if process.chars().any(|c| c.is_whitespace()) {
        return Err("process name cannot contain whitespace".to_string());
    }

    if !process.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')) {
        return Err("process name contains unsupported characters".to_string());
    }

    Ok(())
}

const FAMILY_FALLBACK_KEYS: [&str; 2] = ["systemd", "linux"];

fn get_command_mapping() -> HashMap<(ProcessAction, String), String> {
    let mut map = HashMap::new();

    const KEYS: [&str; 4] = ["systemd", "debian_like", "redhat_like", "linux"];
    const ACTIONS: [ProcessAction; 7] = [
        ProcessAction::Start,
        ProcessAction::Stop,
        ProcessAction::Restart,
        ProcessAction::Enable,
        ProcessAction::Disable,
        ProcessAction::StartEnable,
        ProcessAction::StopDisable,
    ];

    for key in KEYS {
        for action in ACTIONS {
            map.insert((action, key.to_string()), action.template().to_string());
        }
    }

    map
}

fn resolve_command_template(action: ProcessAction, sys: &SystemInfo) -> Option<String> {
    let mut keys: Vec<String> = Vec::new();
    let os_id = sys.os_id.clone();
    if !sys.version_id.is_empty() {
        keys.push(format!("{}-{}", os_id, sys.version_id));
    }
    keys.push(os_id.clone());

    let family_key = family_key(sys);
    if keys.last().map(|last| last.as_str()) != Some(family_key) {
        keys.push(family_key.to_string());
    }

    for &fallback in &FAMILY_FALLBACK_KEYS {
        if keys.iter().all(|existing| existing != fallback) {
            keys.push(fallback.to_string());
        }
    }

    if keys.iter().all(|existing| existing != "linux") {
        keys.push("linux".to_string());
    }

    let map = get_command_mapping();
    for key in keys {
        if let Some(template) = map.get(&(action, key.clone())) {
            return Some(template.clone());
        }
    }

    None
}
