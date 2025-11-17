// Functions: get_log, get_log_query

use std::{collections::BTreeMap, io};

use crate::{
    make_sysinfo_command, make_sysinfo_command_with_argument, send_to_hostd, ReturnInfo, SystemInfo,
};
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug)]
pub struct LogEntry {
    pub month:    String,
    pub day:      i32,
    pub time:     String,
    pub hostname: String,
    pub r#type:   String,
    pub messages: String,
}

#[derive(Debug)]
pub struct Logs {
    pub entries: BTreeMap<String, LogEntry>,
    pub length:  usize,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
enum LogQueryField {
    Month,
    Day,
    Time,
    Hostname,
    Type,
}

#[derive(Deserialize)]
struct LogQueryArgument {
    #[serde(rename = "Search")]
    search:    LogQueryField,
    #[serde(rename = "Parameter")]
    parameter: String,
}

#[derive(Serialize)]
struct LogQueryRequest<'a> {
    #[serde(rename = "Search")]
    search:    LogQueryField,
    #[serde(rename = "Parameter")]
    parameter: &'a str,
}

#[derive(Deserialize)]
struct LogsDto {
    #[serde(rename = "Logs")]
    logs:   BTreeMap<String, LogEntryDto>,
    #[serde(rename = "Length")]
    length: usize,
}

#[derive(Deserialize)]
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

pub fn log_info_structured(_sys: &SystemInfo) -> io::Result<Logs> {
    let cmd = make_sysinfo_command("log_status");
    let output = send_to_hostd(&cmd)?;

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    let dto: LogsDto = serde_json::from_str(&output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse log entries JSON: {}", e),
        )
    })?;

    convert_logs(dto)
}

pub fn log_query_structured(argument: Option<&str>) -> io::Result<Logs> {
    let argument = argument.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "get_log_query requires an argument")
    })?;

    let parsed: LogQueryArgument = serde_json::from_str(argument).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("get_log_query argument parse error: {}", e),
        )
    })?;

    let parameter_owned = parsed.parameter.trim().to_string();
    if parameter_owned.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "get_log_query Parameter cannot be empty",
        ));
    }

    let payload = LogQueryRequest { search: parsed.search, parameter: &parameter_owned };
    let payload_json = serde_json::to_string(&payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to encode get_log_query payload: {}", e),
        )
    })?;

    let cmd = make_sysinfo_command_with_argument("log_query", &payload_json);
    let output = send_to_hostd(&cmd)?;

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    let dto: LogsDto = serde_json::from_str(&output).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse log entries JSON: {}", e),
        )
    })?;

    convert_logs(dto)
}

fn convert_logs(dto: LogsDto) -> io::Result<Logs> {
    let mut entries = BTreeMap::new();
    for (key, entry) in dto.logs {
        entries.insert(
            key,
            LogEntry {
                month:    entry.month,
                day:      entry.day,
                time:     entry.time,
                hostname: entry.hostname,
                r#type:   entry.r#type,
                messages: entry.messages,
            },
        );
    }

    let length = if dto.length == entries.len() { dto.length } else { entries.len() };

    Ok(Logs { length, entries })
}
