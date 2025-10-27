// Functions: get_netif, netif_add, netif_delete, netif_up, netif_down, get_route, route_add, route_delete, get_dns

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::Ipv4Addr;

use crate::{
    execute_host_body, family_commands, join_shell_args, make_sysinfo_command, send_to_hostd,
    shell_quote, value_if_specified, ReturnInfo, SystemInfo,
};
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug)]
pub enum NetworkInterfaceType {
    Virtual,
    Physical,
    Other(String),
}

#[derive(Debug)]
pub enum NetworkInterfaceState {
    Up,
    Down,
    Other(String),
}

#[derive(Debug)]
pub struct NetworkInterfaceInfo {
    pub id: String,
    pub iface_type: NetworkInterfaceType,
    pub ipv4: String,
    pub netmask: String,
    pub mac: String,
    pub broadcast: String,
    pub mtu: u32,
    pub status: NetworkInterfaceState,
}

#[derive(Debug)]
pub struct NetworkInterfaces {
    pub networks: Vec<NetworkInterfaceInfo>,
    pub length: usize,
}

#[derive(Debug)]
pub struct RouteEntry {
    pub destination: String,
    pub via: String,
    pub dev: String,
    pub proto: String,
    pub metric: i32,
    pub scope: String,
    pub src: String,
}

#[derive(Debug)]
pub struct RouteTable {
    pub routes: Vec<RouteEntry>,
    pub length: usize,
}

#[derive(Debug)]
pub struct DnsInfo {
    pub hostname: String,
    pub primary: String,
    pub secondary: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkInterfacesDto {
    networks: HashMap<String, NetworkInterfaceEntryDto>,
    length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkInterfaceEntryDto {
    name: String,
    #[serde(rename = "Type")]
    iface_type: String,
    ipv4: String,
    netmask: String,
    mac: String,
    broadcast: String,
    mtu: u32,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RouteTableDto {
    routes: BTreeMap<String, RouteEntryDto>,
    length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RouteEntryDto {
    destination: String,
    via: String,
    dev: String,
    proto: String,
    metric: i32,
    scope: String,
    src: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DnsInfoDto {
    hostname: String,
    #[serde(rename = "DNS")]
    dns: DnsServersDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DnsServersDto {
    primary: String,
    secondary: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct NetifAddArg {
    nid: String,
    #[serde(rename = "Type")]
    iface_type: String,
    ipv4: String,
    netmask: String,
    mac: String,
    broadcast: String,
    mtu: i32,
    status: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct NetifDeleteArg {
    nid: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct NetifToggleArg {
    nid: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct RouteAddArg {
    destination: String,
    via: String,
    dev: String,
    proto: String,
    metric: i32,
    scope: String,
    src: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct RouteDeleteArg {
    destination: String,
}

pub fn netif_info_structured(_sys: &SystemInfo) -> io::Result<NetworkInterfaces> {
    let cmd = make_sysinfo_command("netif_status");
    let output = send_to_hostd(&cmd)?;

    if let Ok(dto) = serde_json::from_str::<NetworkInterfacesDto>(&output) {
        return Ok(convert_network_interfaces(dto));
    }

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::new(io::ErrorKind::Other, info.message));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to parse network interfaces JSON: {}", output.trim()),
    ))
}

pub fn route_info_structured(_sys: &SystemInfo) -> io::Result<RouteTable> {
    let cmd = make_sysinfo_command("route_status");
    let output = send_to_hostd(&cmd)?;

    if let Ok(dto) = serde_json::from_str::<RouteTableDto>(&output) {
        return Ok(convert_route_table(dto));
    }

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::new(io::ErrorKind::Other, info.message));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to parse route table JSON: {}", output.trim()),
    ))
}

pub fn dns_info_structured(_sys: &SystemInfo) -> io::Result<DnsInfo> {
    let cmd = make_sysinfo_command("dns_status");
    let output = send_to_hostd(&cmd)?;

    if let Ok(dto) = serde_json::from_str::<DnsInfoDto>(&output) {
        return Ok(convert_dns_info(dto));
    }

    if let Ok(info) = serde_json::from_str::<ReturnInfo>(&output) {
        return Err(io::Error::new(io::ErrorKind::Other, info.message));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("failed to parse dns info JSON: {}", output.trim()),
    ))
}

pub fn execute_netif_add(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let mut payload: NetifAddArg = serde_json::from_str(argument)
        .map_err(|e| format!("netif_add payload parse error: {}", e))?;

    payload.nid = payload.nid.trim().to_string();
    if payload.nid.is_empty() {
        return Err("netif_add requires a non-empty Nid".to_string());
    }
    if payload.nid.chars().any(|c| c.is_whitespace()) {
        return Err("netif_add Nid cannot contain whitespace".to_string());
    }

    payload.iface_type = normalize_netif_type_arg(&payload.iface_type)?;
    if payload.iface_type == "Physical" {
        return Err("netif_add does not support creating Physical interfaces".to_string());
    }

    if interface_exists(sys, &payload.nid)? {
        return Err(format!("interface {} already exists", payload.nid));
    }

    payload.status = normalize_netif_status_arg(&payload.status)?;
    let mac = value_if_specified(&payload.mac).map(|s| s.to_string());
    let ipv4 = value_if_specified(&payload.ipv4).map(|s| s.to_string());
    let netmask = value_if_specified(&payload.netmask).map(|s| s.to_string());
    let broadcast = value_if_specified(&payload.broadcast).map(|s| s.to_string());

    let prefix = if ipv4.is_some() {
        let netmask_value = netmask
            .as_ref()
            .ok_or_else(|| "netif_add requires Netmask when Ipv4 is provided".to_string())?;
        Some(netmask_to_prefix(netmask_value)?)
    } else {
        None
    };

    run_ip_command_str(
        sys,
        &[
            "link".to_string(),
            "add".to_string(),
            payload.nid.clone(),
            "type".to_string(),
            "dummy".to_string(),
        ],
    )
    .map_err(|e| format!("failed to create interface {}: {}", payload.nid, e))?;

    let cleanup = |err: String, name: &str| {
        let _ = run_ip_command(sys, &["link", "delete", "dev", name]);
        err
    };

    if let Some(mac_value) = mac.as_ref() {
        let err = format!("failed to set MAC on {}", payload.nid);
        run_ip_command(sys, &["link", "set", "dev", payload.nid.as_str(), "address", mac_value])
            .map_err(|e| cleanup(format!("{}: {}", err, e), &payload.nid))?;
    }

    if payload.mtu > 0 {
        let mtu_string = payload.mtu.to_string();
        let err = format!("failed to set MTU on {}", payload.nid);
        run_ip_command(
            sys,
            &["link", "set", "dev", payload.nid.as_str(), "mtu", mtu_string.as_str()],
        )
        .map_err(|e| cleanup(format!("{}: {}", err, e), &payload.nid))?;
    }

    if let Some(ip_value) = ipv4.as_ref() {
        let prefix_value = prefix.ok_or_else(|| {
            cleanup("netif_add internal error: missing prefix".to_string(), &payload.nid)
        })?;
        let cidr = format!("{}/{}", ip_value, prefix_value);
        let mut args = vec![
            "addr".to_string(),
            "add".to_string(),
            cidr,
            "dev".to_string(),
            payload.nid.clone(),
        ];

        if let Some(broadcast_value) = broadcast.as_ref() {
            args.push("broadcast".to_string());
            args.push(broadcast_value.to_string());
        }

        run_ip_command_str(sys, &args).map_err(|e| {
            cleanup(format!("failed to set IPv4 on {}: {}", payload.nid, e), &payload.nid)
        })?;
    }

    if payload.status == "Up" {
        run_ip_command(sys, &["link", "set", "dev", payload.nid.as_str(), "up"]).map_err(|e| {
            cleanup(format!("failed to bring {} up: {}", payload.nid, e), &payload.nid)
        })?;
    }

    Ok(format!("netif_add: interface {} created", payload.nid))
}

pub fn execute_netif_delete(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let mut payload: NetifDeleteArg = serde_json::from_str(argument)
        .map_err(|e| format!("netif_delete payload parse error: {}", e))?;

    payload.nid = payload.nid.trim().to_string();
    if payload.nid.is_empty() {
        return Err("netif_delete requires a non-empty Nid".to_string());
    }

    if !interface_exists(sys, &payload.nid)? {
        return Err(format!("interface {} not found", payload.nid));
    }

    run_ip_command(sys, &["link", "delete", "dev", payload.nid.as_str()])
        .map_err(|e| format!("failed to delete interface {}: {}", payload.nid, e))?;

    Ok(format!("netif_delete: interface {} removed", payload.nid))
}

pub fn execute_netif_toggle(
    argument: &str,
    sys: &SystemInfo,
    bring_up: bool,
) -> Result<String, String> {
    let mut payload: NetifToggleArg = serde_json::from_str(argument)
        .map_err(|e| format!("netif toggle payload parse error: {}", e))?;

    payload.nid = payload.nid.trim().to_string();
    if payload.nid.is_empty() {
        return Err("netif command requires a non-empty Nid".to_string());
    }

    if !interface_exists(sys, &payload.nid)? {
        return Err(format!("interface {} not found", payload.nid));
    }

    let action = if bring_up { "up" } else { "down" };
    run_ip_command(sys, &["link", "set", "dev", payload.nid.as_str(), action])
        .map_err(|e| format!("failed to bring {} {}: {}", payload.nid, action, e))?;

    Ok(if bring_up {
        format!("netif_up: interface {} is up", payload.nid)
    } else {
        format!("netif_down: interface {} is down", payload.nid)
    })
}

pub fn execute_route_add(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let command: RouteAddArg = serde_json::from_str(argument)
        .map_err(|e| format!("route_add payload parse error: {}", e))?;

    let destination = command.destination.trim().to_string();
    if destination.is_empty() {
        return Err("route_add requires Destination".to_string());
    }

    let mut args = vec!["route".to_string(), "add".to_string(), destination.clone()];

    if let Some(via) = value_if_specified(&command.via) {
        args.push("via".to_string());
        args.push(via.to_string());
    }

    if let Some(dev) = value_if_specified(&command.dev) {
        args.push("dev".to_string());
        args.push(dev.to_string());
    }

    if let Some(proto) = value_if_specified(&command.proto) {
        args.push("proto".to_string());
        args.push(proto.to_string());
    }

    if command.metric > 0 {
        args.push("metric".to_string());
        args.push(command.metric.to_string());
    }

    if let Some(scope) = value_if_specified(&command.scope) {
        args.push("scope".to_string());
        args.push(scope.to_string());
    }

    if let Some(src) = value_if_specified(&command.src) {
        args.push("src".to_string());
        args.push(src.to_string());
    }

    run_ip_command_str(sys, &args).map_err(|e| format!("route_add execution error: {}", e))?;

    Ok(format!("route_add: route {} created", destination))
}

pub fn execute_route_delete(argument: &str, sys: &SystemInfo) -> Result<String, String> {
    let command: RouteDeleteArg = serde_json::from_str(argument)
        .map_err(|e| format!("route_delete payload parse error: {}", e))?;

    let destination = command.destination.trim().to_string();
    if destination.is_empty() {
        return Err("route_delete requires Destination".to_string());
    }

    run_ip_command_str(sys, &["route".to_string(), "del".to_string(), destination.clone()])
        .map_err(|e| format!("route_delete execution error: {}", e))?;

    Ok(format!("route_delete: route {} removed", destination))
}

fn convert_network_interfaces(dto: NetworkInterfacesDto) -> NetworkInterfaces {
    let mut entries: Vec<(String, NetworkInterfaceEntryDto)> = dto.networks.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let networks =
        entries.into_iter().map(|(id, entry)| convert_network_interface(id, entry)).collect();

    NetworkInterfaces { networks, length: dto.length }
}

fn convert_network_interface(id: String, entry: NetworkInterfaceEntryDto) -> NetworkInterfaceInfo {
    let resolved_id = if entry.name.is_empty() { id } else { entry.name.clone() };

    NetworkInterfaceInfo {
        id: resolved_id,
        iface_type: parse_network_interface_type(&entry.iface_type),
        ipv4: entry.ipv4,
        netmask: entry.netmask,
        mac: entry.mac,
        broadcast: entry.broadcast,
        mtu: entry.mtu,
        status: parse_network_interface_status(&entry.status),
    }
}

fn convert_route_table(dto: RouteTableDto) -> RouteTable {
    let mut entries: Vec<(String, RouteEntryDto)> = dto.routes.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let routes = entries
        .into_iter()
        .map(|(destination, entry)| RouteEntry {
            destination: if entry.destination.is_empty() { destination } else { entry.destination },
            via: entry.via,
            dev: entry.dev,
            proto: entry.proto,
            metric: entry.metric,
            scope: entry.scope,
            src: entry.src,
        })
        .collect();

    RouteTable { routes, length: dto.length }
}

fn convert_dns_info(dto: DnsInfoDto) -> DnsInfo {
    DnsInfo { hostname: dto.hostname, primary: dto.dns.primary, secondary: dto.dns.secondary }
}

fn parse_network_interface_type(value: &str) -> NetworkInterfaceType {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "virtual" => NetworkInterfaceType::Virtual,
        "physical" => NetworkInterfaceType::Physical,
        _ => NetworkInterfaceType::Other(value.to_string()),
    }
}

fn parse_network_interface_status(value: &str) -> NetworkInterfaceState {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "up" => NetworkInterfaceState::Up,
        "down" => NetworkInterfaceState::Down,
        _ => NetworkInterfaceState::Other(value.to_string()),
    }
}

impl NetworkInterfaceType {
    pub fn as_str(&self) -> &str {
        match self {
            NetworkInterfaceType::Virtual => "Virtual",
            NetworkInterfaceType::Physical => "Physical",
            NetworkInterfaceType::Other(value) => value.as_str(),
        }
    }
}

impl NetworkInterfaceState {
    pub fn as_str(&self) -> &str {
        match self {
            NetworkInterfaceState::Up => "Up",
            NetworkInterfaceState::Down => "Down",
            NetworkInterfaceState::Other(value) => value.as_str(),
        }
    }
}

fn interface_exists(sys: &SystemInfo, name: &str) -> Result<bool, String> {
    let commands = family_commands(sys);
    let body = format!("{} link show dev {}\n", commands.ip, shell_quote(name));
    let result = execute_host_body(&body)?;
    Ok(result.status == 0)
}

fn run_ip_command(sys: &SystemInfo, args: &[&str]) -> Result<(), String> {
    let arg_list = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    run_ip_command_str(sys, &arg_list)
}

fn run_ip_command_str(sys: &SystemInfo, args: &[String]) -> Result<(), String> {
    let joined = join_shell_args(args);
    let commands = family_commands(sys);
    let body = format!("{} {}\n", commands.ip, joined);
    let result = execute_host_body(&body)?;
    if result.status == 0 {
        Ok(())
    } else if result.output.trim().is_empty() {
        Err(format!("ip {} failed with status {}", joined, result.status))
    } else {
        Err(result.output.trim().to_string())
    }
}

fn netmask_to_prefix(netmask: &str) -> Result<u32, String> {
    let addr: Ipv4Addr =
        netmask.parse().map_err(|e| format!("invalid netmask {}: {}", netmask, e))?;

    let bits = u32::from(addr);
    let prefix = bits.count_ones();

    if bits << prefix != 0 {
        return Err(format!("netmask {} is not contiguous", netmask));
    }

    Ok(prefix)
}

fn normalize_netif_type_arg(value: &str) -> Result<String, String> {
    let normalized = value.trim();
    match normalized.to_ascii_lowercase().as_str() {
        "virtual" => Ok("Virtual".to_string()),
        "physical" => Ok("Physical".to_string()),
        _ => Err(format!("unsupported interface type: {}", value)),
    }
}

fn normalize_netif_status_arg(value: &str) -> Result<String, String> {
    let normalized = value.trim();
    match normalized.to_ascii_lowercase().as_str() {
        "up" => Ok("Up".to_string()),
        "down" => Ok("Down".to_string()),
        _ => Err(format!("unsupported interface status: {}", value)),
    }
}
