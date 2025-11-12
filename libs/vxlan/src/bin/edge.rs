use chm_vxlan::{Result, edge_create_vxlan, list_vxlans};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> Result<()> {
    edge_create_vxlan(100, None, Ipv4Addr::new(172, 18, 0, 10), Some("10.100.0.21/24"), &[])
        .await?;
    edge_create_vxlan(200, None, Ipv4Addr::new(172, 18, 0, 10), Some("10.200.0.22/24"), &[])
        .await?;
    println!("VXLANs: {:?}", list_vxlans().await?);
    Ok(())
}
