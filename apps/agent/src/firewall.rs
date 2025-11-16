// Functions: get_firewall, firewall_add, firewall_delete, firewall_edit_status,
// firewall_edit_policy

use std::io;

use crate::{
    execute_host_body, family_commands, join_shell_args, make_sysinfo_command, send_to_hostd,
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

pub fn firewall_info_structured(_sys: &SystemInfo) -> io::Result<FirewallStatus> {
    let cmd = make_sysinfo_command("firewall_status");
    let output = send_to_hostd(&cmd)?;

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

pub fn execute_firewall_add(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallAddArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_add payload parse error: {}", e))?;

    let mut args = vec![
        "-A".to_string(),
        payload.chain.as_str().to_string(),
        "-j".to_string(),
        payload.target.as_str().to_string(),
    ];

    if let Some(protocol) = value_if_specified(&payload.protocol) {
        args.push("-p".to_string());
        args.push(protocol.to_string());
    }

    if let Some(in_iface) = value_if_specified(&payload.in_field) {
        args.push("-i".to_string());
        args.push(in_iface.to_string());
    }

    if let Some(out_iface) = value_if_specified(&payload.out_field) {
        args.push("-o".to_string());
        args.push(out_iface.to_string());
    }

    if let Some(source) = value_if_specified(&payload.source) {
        args.push("-s".to_string());
        args.push(source.to_string());
    }

    if let Some(destination) = value_if_specified(&payload.destination) {
        args.push("-d".to_string());
        args.push(destination.to_string());
    }

    args.extend(parse_options(&payload.options));

    run_firewall_mutation(sys, &args)?;

    Ok(format!(
        "firewall_add: added rule to {} with target {}",
        payload.chain.as_str(),
        payload.target.as_str()
    ))
}

pub fn execute_firewall_delete(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallDeleteArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_delete payload parse error: {}", e))?;

    if payload.rule_id <= 0 {
        return Err("firewall_delete requires RuleId greater than 0".to_string());
    }

    let args =
        vec!["-D".to_string(), payload.chain.as_str().to_string(), payload.rule_id.to_string()];

    run_firewall_mutation(sys, &args)?;

    Ok(format!("firewall_delete: removed rule from {}", payload.chain.as_str()))
}

pub fn execute_firewall_edit_status(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallEditStatusArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_edit_status payload parse error: {}", e))?;

    match payload.status {
        FirewallStatusArg::Active => {
            set_firewall_policies(
                sys,
                &[("INPUT", "DROP"), ("FORWARD", "DROP"), ("OUTPUT", "ACCEPT")],
            )?;
            Ok("firewall_edit_status: firewall activated".to_string())
        }
        FirewallStatusArg::Inactive => {
            set_firewall_policies(
                sys,
                &[("INPUT", "ACCEPT"), ("FORWARD", "ACCEPT"), ("OUTPUT", "ACCEPT")],
            )?;
            Ok("firewall_edit_status: firewall deactivated".to_string())
        }
    }
}

pub fn execute_firewall_edit_policy(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let payload: FirewallEditPolicyArg = serde_json::from_str(argument)
        .map_err(|e| format!("firewall_edit_policy payload parse error: {}", e))?;

    set_firewall_policies(sys, &[(payload.chain.as_str(), payload.policy.as_str())])?;

    Ok(format!(
        "firewall_edit_policy: set {} policy to {}",
        payload.chain.as_str(),
        payload.policy.as_str()
    ))
}

fn convert_firewall_status(dto: FirewallStatusDto) -> FirewallStatus {
    let status = parse_firewall_status_state(&dto.status);
    let chains = dto.chains.into_iter().map(convert_firewall_chain).collect();

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

fn parse_options(options: &str) -> Vec<String> {
    options
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

fn run_firewall_mutation(sys: &SystemInfo, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("insufficient arguments for firewall mutation".to_string());
    }

    let joined_args = join_shell_args(args);
    let commands = family_commands(sys);
    let mut errors = Vec::new();

    for cmd in commands.iptables_candidates.iter() {
        let body = format!("{} {}\n", cmd, joined_args);
        let result = execute_host_body(&body)?;
        if result.status == 0 {
            return Ok(());
        }

        if result.output.trim().is_empty() {
            errors.push(format!("{} exited with status {}", cmd, result.status));
        } else {
            errors.push(format!("{}: {}", cmd, result.output.trim()));
        }
    }

    if errors.is_empty() {
        Err("no firewall mutation commands available".to_string())
    } else {
        Err(errors.join("; "))
    }
}

fn set_firewall_policies(sys: &SystemInfo, policies: &[(&str, &str)]) -> Result<(), String> {
    for (chain, policy) in policies {
        let args = vec!["-P".to_string(), chain.to_string(), policy.to_string()];
        run_firewall_mutation(sys, &args)
            .map_err(|e| format!("failed to set policy for {}: {}", chain, e))?;
    }
    Ok(())
}
