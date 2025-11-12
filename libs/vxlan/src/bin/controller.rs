use chm_vxlan::{Result, controller_create_vxlan, list_vxlans};

#[tokio::main]
async fn main() -> Result<()> {
    controller_create_vxlan(100, None, None).await?;
    controller_create_vxlan(200, None, None).await?;
    println!("VXLANs: {:?}", list_vxlans().await?);
    Ok(())
}
