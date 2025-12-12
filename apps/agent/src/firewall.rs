// Functions: get_firewall, firewall_add, firewall_delete, firewall_edit_status,
// firewall_edit_policy

use std::io;

use crate::{
    make_sysinfo_command, make_sysinfo_command_with_argument, parse_return_info, send_to_hostd,
    value_if_specified, ReturnInfo, SystemInfo,
};
use serde::{de, Deserialize, Serialize};
use serde_json;

#[derive(Debug)]
pub enum FirewallStatusState {
    Active,
    Inactive,
    Unknown(String),
}

#[derive(Debug)]
pub enum FirewallPolicy {
    Accept,
    Drop,
    Reject,
    Other(String),
}

#[derive(Debug)]
pub struct FirewallRule {
    pub id:            String,
    pub target:        FirewallPolicy,
    pub protocol:      String,
    pub in_interface:  String,
    pub out_interface: String,
    pub source:        String,
    pub destination:   String,
    pub options:       String,
}

#[derive(Debug)]
pub struct FirewallChain {
    pub name:         String,
    pub policy:       FirewallPolicy,
    pub rules:        Vec<FirewallRule>,
    pub rules_length: usize,
}

#[derive(Debug)]
pub struct FirewallStatus {
    pub status: FirewallStatusState,
    pub chains: Vec<FirewallChain>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallStatusDto {
    status: String,
    chains: Vec<FirewallChainDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallChainDto {
    name:         String,
    policy:       String,
    rules:        Vec<FirewallRuleDto>,
    #[serde(rename = "Rules_Length")]
    rules_length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FirewallRuleDto {
    id:          String,
    target:      String,
    protocol:    String,
    #[serde(rename = "In")]
    in_field:    String,
    #[serde(rename = "Out")]
    out_field:   String,
    source:      String,
    destination: String,
    options:     String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallChainArg {
    Input,
    Forward,
    Output,
}

impl FirewallChainArg {
    fn as_str(self) -> &'static str {
        match self {
            FirewallChainArg::Input => "INPUT",
            FirewallChainArg::Forward => "FORWARD",
            FirewallChainArg::Output => "OUTPUT",
        }
    }
}

impl Serialize for FirewallChainArg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FirewallChainArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let normalized = raw.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "INPUT" => Ok(FirewallChainArg::Input),
            "FORWARD" => Ok(FirewallChainArg::Forward),
            "OUTPUT" => Ok(FirewallChainArg::Output),
            other => Err(de::Error::custom(format!("unsupported chain: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallTargetArg {
    Accept,
    Drop,
    Reject,
}

impl FirewallTargetArg {
    fn as_str(self) -> &'static str {
        match self {
            FirewallTargetArg::Accept => "ACCEPT",
            FirewallTargetArg::Drop => "DROP",
            FirewallTargetArg::Reject => "REJECT",
        }
    }
}

impl Serialize for FirewallTargetArg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FirewallTargetArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let normalized = raw.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "ACCEPT" => Ok(FirewallTargetArg::Accept),
            "DROP" => Ok(FirewallTargetArg::Drop),
            "REJECT" => Ok(FirewallTargetArg::Reject),
            other => Err(de::Error::custom(format!("unsupported target: {}", other))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallStatusArg {
    Active,
    Inactive,
}

impl FirewallStatusArg {
    fn as_str(self) -> &'static str {
        match self {
            FirewallStatusArg::Active => "ACTIVE",
            FirewallStatusArg::Inactive => "INACTIVE",
        }
    }
}

impl Serialize for FirewallStatusArg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FirewallStatusArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let normalized = raw.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "ACTIVE" => Ok(FirewallStatusArg::Active),
            "INACTIVE" => Ok(FirewallStatusArg::Inactive),
            other => Err(de::Error::custom(format!("unsupported status: {}", other))),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct FirewallDeleteArg {
    chain:   FirewallChainArg,
    #[serde(rename = "RuleId")]
    rule_id: i32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct FirewallEditStatusArg {
    status: FirewallStatusArg,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct FirewallEditPolicyArg {
    chain:  FirewallChainArg,
    policy: FirewallTargetArg,
}

pub async fn firewall_info_structured(_sys: &SystemInfo) -> io::Result<FirewallStatus> {
    let cmd = make_sysinfo_command("firewall_status");
    let output = send_to_hostd(&cmd).await?;

    if let Ok(status) = serde_json::from_str::<FirewallStatusDto>(&output) {
        return Ok(convert_firewall_status(status));
    }

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::other(info.message));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to parse firewall status JSON: {}", output.trim()),
    ))
}

pub async fn execute_firewall_add(argument: &str, _sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallAddArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_add payload parse error: {}", e))?;
    if value_if_specified(&payload.protocol).is_none()
        && payload.options.to_ascii_lowercase().contains("port")
    {
        return Err("firewall_add: specifying ports requires Protocol".to_string());
    }

    let cmd = make_sysinfo_command_with_argument("firewall_add", argument);
    let output = send_to_hostd(&cmd).await.map_err(|e| format!("firewall_add via hostd: {}", e))?;
    parse_return(output, "firewall_add")
}

pub async fn execute_firewall_delete(argument: &str, _sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallDeleteArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_delete payload parse error: {}", e))?;
    if payload.rule_id <= 0 {
        return Err("firewall_delete requires RuleId greater than 0".to_string());
    }

    let cmd = make_sysinfo_command_with_argument("firewall_delete", argument);
    let output =
        send_to_hostd(&cmd).await.map_err(|e| format!("firewall_delete via hostd: {}", e))?;
    parse_return(output, "firewall_delete")
}

pub async fn execute_firewall_edit_status(
    argument: &str,
    _sys: &SystemInfo,
) -> Result<String, String> {
    let _payload: FirewallEditStatusArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_edit_status payload parse error: {}", e))?;

    let cmd = make_sysinfo_command_with_argument("firewall_edit_status", argument);
    let output =
        send_to_hostd(&cmd).await.map_err(|e| format!("firewall_edit_status via hostd: {}", e))?;
    parse_return(output, "firewall_edit_status")
}

pub async fn execute_firewall_edit_policy(
    argument: &str,
    _sys: &SystemInfo,
) -> Result<String, String> {
    let payload: FirewallEditPolicyArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_edit_policy payload parse error: {}", e))?;
    if matches!(payload.chain, FirewallChainArg::Forward) {
        return Err("firewall_edit_policy: FORWARD chain is not managed".to_string());
    }

    let cmd = make_sysinfo_command_with_argument("firewall_edit_policy", argument);
    let output =
        send_to_hostd(&cmd).await.map_err(|e| format!("firewall_edit_policy via hostd: {}", e))?;
    parse_return(output, "firewall_edit_policy")
}

fn parse_return(raw: String, op: &str) -> Result<String, String> {
    match parse_return_info(&raw) {
        Ok(info) => match info.status {
            crate::ReturnStatus::Ok => Ok(info.message),
            crate::ReturnStatus::Err | crate::ReturnStatus::Other(_) => {
                Err(format!("{} failed: {}", op, info.message))
            }
        },
        Err(_) => Ok(raw.trim().to_string()),
    }
}

fn convert_firewall_status(dto: FirewallStatusDto) -> FirewallStatus {
    let status = parse_firewall_status_state(&dto.status);
    let chains = dto
        .chains
        .into_iter()
        .filter(|chain| {
            matches!(chain.name.to_ascii_uppercase().as_str(), "INPUT" | "FORWARD" | "OUTPUT")
        })
        .map(convert_firewall_chain)
        .collect();

    FirewallStatus { status, chains }
}

fn convert_firewall_chain(dto: FirewallChainDto) -> FirewallChain {
    let rules: Vec<FirewallRule> = dto.rules.into_iter().map(convert_firewall_rule).collect();
    let length = if dto.rules_length == 0 { rules.len() } else { dto.rules_length };

    FirewallChain {
        name: dto.name,
        policy: parse_firewall_policy(&dto.policy),
        rules,
        rules_length: length,
    }
}

fn convert_firewall_rule(dto: FirewallRuleDto) -> FirewallRule {
    FirewallRule {
        id:            dto.id,
        target:        parse_firewall_policy(&dto.target),
        protocol:      dto.protocol,
        in_interface:  dto.in_field,
        out_interface: dto.out_field,
        source:        dto.source,
        destination:   dto.destination,
        options:       dto.options,
    }
}

fn parse_firewall_status_state(value: &str) -> FirewallStatusState {
    match value.to_ascii_lowercase().as_str() {
        "active" => FirewallStatusState::Active,
        "inactive" => FirewallStatusState::Inactive,
        _ => FirewallStatusState::Unknown(value.to_string()),
    }
}

fn parse_firewall_policy(value: &str) -> FirewallPolicy {
    match value.to_ascii_uppercase().as_str() {
        "ACCEPT" => FirewallPolicy::Accept,
        "DROP" => FirewallPolicy::Drop,
        "REJECT" => FirewallPolicy::Reject,
        _ => FirewallPolicy::Other(value.to_string()),
    }
}

impl FirewallStatusState {
    pub fn as_str(&self) -> &str {
        match self {
            FirewallStatusState::Active => "active",
            FirewallStatusState::Inactive => "inactive",
            FirewallStatusState::Unknown(value) => value.as_str(),
        }
    }
}

impl FirewallPolicy {
    pub fn as_str(&self) -> &str {
        match self {
            FirewallPolicy::Accept => "ACCEPT",
            FirewallPolicy::Drop => "DROP",
            FirewallPolicy::Reject => "REJECT",
            FirewallPolicy::Other(value) => value.as_str(),
        }
    }
}
