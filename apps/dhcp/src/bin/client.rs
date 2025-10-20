use chm_grpc::{
    dhcp::{
        dhcp_service_client::DhcpServiceClient, AllocateIpRequest, CreateZoneRequest,
        DeleteZoneRequest, Empty, ReleaseIpRequest, ZoneIdentifier,
    },
    tonic::transport::Channel,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// 初始化 gRPC 連線
async fn init_grpc_channel() -> Result<DhcpServiceClient<Channel>> {
    let channel = Channel::from_static("http://[::1]:50051").connect().await?;
    Ok(DhcpServiceClient::new(channel))
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = init_grpc_channel().await?;

    println!("✅ 測試流程開始");

    // 1. 建立 zone
    create_zone(&mut client).await?;

    // 2. 建立同名 zone (預期錯誤)
    expect_error("重複建立 Zone", create_zone(&mut client).await);

    // 3. 列出 zones
    list_zones(&mut client).await?;

    // 4. 分配一個 IP
    let allocated_ip = allocate_ip(&mut client).await?;

    // 5. 列出可用 IP
    list_available_ips(&mut client).await?;

    // 6. 釋放剛分配的 IP
    release_ip(&mut client, &allocated_ip).await?;

    // 7. 在不存在的 Zone分配 IP (預期錯誤)
    expect_error("在不存在 Zone 分配 IP", allocate_ip_nonexistent(&mut client).await);

    // 8. 在不存在的 Zone釋放 IP (預期錯誤)
    expect_error("在不存在 Zone 釋放 IP", release_ip_nonexistent(&mut client).await);

    // 9. 刪除 Zone
    delete_zone(&mut client).await?;

    // 10. 刪除不存在的 Zone (預期錯誤)
    expect_error("刪除不存在的 Zone", delete_zone(&mut client).await);

    println!("✅ 所有測試完成");
    Ok(())
}

/// 如果執行成功，報錯；若執行失敗（符合預期），顯示錯誤訊息
fn expect_error(description: &str, result: Result<()>) {
    match result {
        Ok(_) => panic!("❌ 測試失敗：{description} 應該要失敗，但成功了"),
        Err(e) => println!("✅ 預期錯誤 ({description}): {e}"),
    }
}

/// 建立 Zone
async fn create_zone(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  建立 Zone...");
    let req = CreateZoneRequest {
        zone_name: "test_zone".to_string(),
        vni:       100,
        cidr:      "192.168.56.0/24".to_string(),
    };
    let resp = client.create_zone(req).await?;
    let reply = resp.into_inner();
    println!("✅ CreateZone Response: {}", reply.message);
    Ok(())
}

/// 列出所有 Zones
async fn list_zones(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  列出 Zones...");
    let resp = client.list_zones(Empty {}).await?;
    let reply = resp.into_inner();
    println!("✅ Zones:");
    for zone in reply.zones {
        println!("   - {} (vni: {})", zone.name, zone.vni);
    }
    Ok(())
}

/// 分配 IP
async fn allocate_ip(client: &mut DhcpServiceClient<Channel>) -> Result<String> {
    println!("➡️  分配 IP...");
    let req = AllocateIpRequest { zone_name: "test_zone".to_string() };
    let resp = client.allocate_ip(req).await?;
    let reply = resp.into_inner();
    println!("✅ 分配到 IP: {}", reply.ip);
    Ok(reply.ip)
}

/// 在不存在的 Zone分配 IP (預期錯誤)
async fn allocate_ip_nonexistent(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  嘗試在不存在的 Zone 分配 IP...");
    let req = AllocateIpRequest { zone_name: "nonexistent_zone".to_string() };
    client.allocate_ip(req).await?;
    Ok(())
}

/// 列出可用 IP
async fn list_available_ips(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  列出可用 IP...");
    let req = ZoneIdentifier { zone_name: "test_zone".to_string() };
    let resp = client.list_available_ips(req).await?;
    let reply = resp.into_inner();
    println!("✅ 可用 IP:");
    for ip in reply.ips {
        println!("   - {ip}");
    }
    Ok(())
}

/// 釋放 IP
async fn release_ip(client: &mut DhcpServiceClient<Channel>, ip: &str) -> Result<()> {
    println!("➡️  釋放 IP {ip}...");
    let req = ReleaseIpRequest { zone_name: "test_zone".to_string(), ip: ip.to_string() };
    let resp = client.release_ip(req).await?;
    let reply = resp.into_inner();
    println!("✅ ReleaseIp Response: {}", reply.message);
    Ok(())
}

/// 在不存在的 Zone釋放 IP (預期錯誤)
async fn release_ip_nonexistent(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  嘗試在不存在的 Zone 釋放 IP...");
    let req = ReleaseIpRequest {
        zone_name: "nonexistent_zone".to_string(),
        ip:        "192.168.56.99".to_string(),
    };
    client.release_ip(req).await?;
    Ok(())
}

/// 刪除 Zone
async fn delete_zone(client: &mut DhcpServiceClient<Channel>) -> Result<()> {
    println!("➡️  刪除 Zone...");
    let req = DeleteZoneRequest { zone_name: "test_zone".to_string() };
    let resp = client.delete_zone(req).await?;
    let reply = resp.into_inner();
    println!("✅ DeleteZone Response: {}", reply.message);
    Ok(())
}
