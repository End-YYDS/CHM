use crate::{ConResult, GlobalConfig};
use backoff::{future::retry, ExponentialBackoff};
use chm_grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};
pub(crate) mod ca;
pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod ldap;

#[derive(Debug)]
pub(crate) struct GrpcClients {
    pub ca: ca::ClientCA,
    // Todo: 其他服務的客戶端可以在這裡添加
}

#[allow(unused)]
#[derive(Debug)]
pub(crate) enum ServiceName {
    Controller,
    Mca,
}
impl AsRef<str> for ServiceName {
    fn as_ref(&self) -> &str {
        match self {
            ServiceName::Controller => "controller.Controller",
            ServiceName::Mca => "ca.CA",
        }
    }
}
async fn ca_grpc_connection_init(mca_info: String, tls: ClientTlsConfig) -> ConResult<Channel> {
    tracing::debug!("初始化 CA gRPC 連線...");
    // let channel =
    // Endpoint::from_shared(mca_info)?.tls_config(tls)?.connect().await?;
    let endpoint = Endpoint::from_shared(mca_info)?.tls_config(tls)?;
    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    };
    let channel = retry(backoff, || async {
        match endpoint.connect().await {
            Ok(ch) => {
                tracing::info!("CA gRPC Channel 已建立");
                Ok(ch)
            }
            Err(e) => {
                tracing::warn!("連線失敗: {e}，等待後重試...");
                Err(backoff::Error::transient(e))
            }
        }
    })
    .await?;
    tracing::debug!("CA gRPC Channel已建立");
    Ok(channel)
}
pub(crate) async fn init_channel() -> ConResult<GrpcClients> {
    tracing::info!("初始化gRPC通道...");
    let (root_cert, client_cert, client_key, mca_info) = {
        let r = GlobalConfig::read().await;
        let (root, cert, key, ca) = (
            &r.settings.certificate.root_ca,
            &r.settings.certificate.client_cert,
            &r.settings.certificate.client_key,
            &r.settings.server.ca_server,
        );

        if root.is_empty() || cert.is_empty() || key.is_empty() || ca.is_empty() {
            tracing::error!("GlobalsVar 中的憑證未正確初始化");
            return Err("憑證取得或設定失敗".into());
        }
        let root = std::fs::read(root).expect("無法讀取 CA 根憑證");
        let cert = std::fs::read(cert).expect("無法讀取客戶端憑證");
        let key = std::fs::read(key).expect("無法讀取客戶端金鑰");

        (root, cert, key, ca.clone())
    };
    tracing::debug!("讀取憑證及金鑰成功");
    let ca_certificate = Certificate::from_pem(root_cert);
    let client_identity = Identity::from_pem(client_cert, client_key);
    let tls = ClientTlsConfig::new().ca_certificate(ca_certificate).identity(client_identity);
    tracing::info!("TLS 配置已建立");
    tracing::info!("gRPC 正在初始化...");
    let ca_channel = ca_grpc_connection_init(mca_info, tls.clone()).await?;
    // Todo: 其他建立的Channel可以在這裡添加
    tracing::debug!("gRPC 通道已初始化");
    tracing::debug!("執行健康檢查...");
    health_check(ca_channel.clone(), ServiceName::Mca).await?;
    // Todo: 其他服務的健康檢查可以在這裡添加
    tracing::debug!("健康檢查完成");
    tracing::debug!("建立 gRPC 客戶端...");
    let ca_client = ca::ClientCA::new(ca_channel.clone());
    // Todo: 其他服務的客戶端可以在這裡添加
    tracing::debug!("gRPC 客戶端已建立");
    let clients = GrpcClients { ca: ca_client }; // Todo: 其他服務的客戶端可以在這裡添加
    tracing::info!("gRPC 通道初始化完成");
    Ok(clients)
}
async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> crate::ConResult<()> {
    let svc = service_name.as_ref(); // &str
    tracing::info!("執行{svc}健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health.check(HealthCheckRequest { service: svc.into() }).await?.into_inner();
    tracing::info!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
