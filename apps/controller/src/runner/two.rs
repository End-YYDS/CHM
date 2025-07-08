use crate::{
    communication::{ca::ClientCA, ca_grpc_connection_init, health_check, ServiceName},
    ConResult,
};

pub async fn run() -> ConResult<()> {
    tracing::debug!("Controller 正在運行...");
    let channel = ca_grpc_connection_init().await?;
    tracing::debug!("gRPC Channel 已建立");
    tracing::debug!("執行健康檢查...");
    health_check(channel.clone(), ServiceName::Mca).await?;
    tracing::debug!("健康檢查完成");
    tracing::debug!("建立 CA gRPC 客戶端...");
    let mut client_ca = ClientCA::new(channel);
    tracing::debug!("CA gRPC 客戶端已建立");
    let ret = client_ca.get_all_certificates().await?;
    tracing::debug!("已獲取 {} 張憑證", ret.len());
    Ok(())
}
