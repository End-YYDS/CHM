mod error;
use futures::TryStreamExt;

use rtnetlink::{
    Handle, LinkVxlan, new_connection,
    packet_route::link::{InfoData, InfoKind, InfoVxlan, LinkAttribute, LinkInfo},
};

use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr},
};

use crate::error::VxlanError;
pub type Result<T> = std::result::Result<T, VxlanError>;

async fn nl() -> Result<(Handle, tokio::task::JoinHandle<()>)> {
    let (conn, handle, _) = new_connection()?;
    let j = tokio::spawn(conn);
    Ok((handle, j))
}

async fn ifindex(handle: &Handle, name: &str) -> Result<u32> {
    let mut q = handle.link().get().match_name(name.to_string()).execute();
    let msg = q.try_next().await?.ok_or_else(|| VxlanError::InterfaceNotFound(name.to_string()))?;
    Ok(msg.header.index)
}

pub fn detect_underlay_iface() -> Result<String> {
    let f = File::open("/proc/net/route")?;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let iface = cols[0];
        let dest_hex = cols[1];
        let flags_hex = cols[3];
        if dest_hex == "00000000" {
            let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
            if flags & 0x2 != 0 {
                return Ok(iface.to_string());
            }
        }
    }
    Err(VxlanError::NoDefaultRoute)
}

pub fn suggest_overlay_ip(vni: u16, role: &str, idx: u16) -> String {
    match role {
        "controller" => format!("10.{}.0.1/24", vni),
        _ => format!("10.{}.0.{}/24", vni, 20 + idx),
    }
}

async fn add_ipv4(handle: &Handle, ifname: &str, cidr: &str) -> Result<()> {
    let idx = ifindex(handle, ifname).await?;
    let (ip, pfx) = cidr.split_once('/').ok_or(VxlanError::InvalidCidr)?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| VxlanError::InvalidIpv4(ip.to_string()))?;
    let pfx: u8 = pfx.parse().map_err(|_| VxlanError::InvalidPrefix(pfx.to_string()))?;
    handle.address().add(idx, IpAddr::V4(ip), pfx).execute().await?;
    Ok(())
}

pub async fn list_vxlans() -> Result<Vec<(String, u32)>> {
    let (handle, _j) = nl().await?;
    let mut links = handle.link().get().execute();
    let mut out = Vec::new();
    while let Some(msg) = links.try_next().await? {
        let mut name: Option<String> = None;
        let mut vni: Option<u32> = None;
        let mut is_vxlan = false;
        for nla in &msg.attributes {
            match nla {
                LinkAttribute::IfName(n) => name = Some(n.clone()),
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        match info {
                            LinkInfo::Kind(InfoKind::Vxlan) => {
                                is_vxlan = true;
                            }
                            LinkInfo::Data(InfoData::Vxlan(vxlans)) if is_vxlan => {
                                for vx in vxlans {
                                    if let InfoVxlan::Id(id) = vx {
                                        vni = Some(*id);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if let (Some(n), Some(id)) = (name, vni) {
            out.push((n, id));
        }
    }
    Ok(out)
}

pub async fn delete_vxlan(name: &str) -> Result<()> {
    let (handle, _j) = nl().await?;
    if let Ok(idx) = ifindex(&handle, name).await {
        handle.link().del(idx).execute().await?;
    }
    Ok(())
}

pub async fn controller_create_vxlan(
    vni: u32,
    underlay_if: Option<&str>,
    overlay_ip: Option<&str>,
) -> Result<String> {
    let vxname = format!("vxlan{}", vni);
    let (handle, _j) = nl().await?;
    let underlay = underlay_if
        .map(|s| s.to_string())
        .unwrap_or_else(|| detect_underlay_iface().expect("detect underlay"));
    let uidx = ifindex(&handle, &underlay).await?;
    if ifindex(&handle, &vxname).await.is_err() {
        let msg = LinkVxlan::new(&vxname, vni).dev(uidx).port(4789).up().build();
        handle.link().add(msg).execute().await?;
    }
    let ip = overlay_ip
        .map(|s| s.to_string())
        .unwrap_or_else(|| suggest_overlay_ip(vni as u16, "controller", 0));
    add_ipv4(&handle, &vxname, &ip).await?;
    Ok(vxname)
}

pub async fn edge_create_vxlan(
    vni: u32,
    underlay_if: Option<&str>,
    controller_underlay: Ipv4Addr,
    overlay_ip: Option<&str>,
    _multi_remote: &[Ipv4Addr],
) -> Result<String> {
    let vxname = format!("vxlan{}", vni);
    let (handle, _j) = nl().await?;
    let underlay = underlay_if
        .map(|s| s.to_string())
        .unwrap_or_else(|| detect_underlay_iface().expect("detect underlay"));
    let uidx = ifindex(&handle, &underlay).await?;
    if ifindex(&handle, &vxname).await.is_err() {
        let msg = LinkVxlan::new(&vxname, vni)
            .dev(uidx)
            .remote(controller_underlay)
            .port(4789)
            .up()
            .build();
        handle.link().add(msg).execute().await?;
    }
    let ip = overlay_ip.map(|s| s.to_string()).unwrap_or_else(|| format!("10.{}.0.20/24", vni));
    add_ipv4(&handle, &vxname, &ip).await?;
    Ok(vxname)
}
