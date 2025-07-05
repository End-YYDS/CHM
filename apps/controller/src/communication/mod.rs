use grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};

use crate::ConResult;
pub mod ca;
#[allow(unused)]
#[derive(Debug)]
pub enum ServiceName {
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
pub async fn grpc_connection_init() -> ConResult<Channel> {
    let (root_cert, client_cert, client_key, mca_info) = {
        let lock = crate::globals_lock().await;
        let r = lock.read().await;
        if let (Some(root), Some(cert), Some(key), Some(ca)) =
            (&r.root_ca_cert, &r.client_cert, &r.client_key, &r.mca_info)
        {
            (root.clone(), cert.clone(), key.clone(), ca.clone())
        } else {
            tracing::error!("GlobalsVar 中的憑證未正確初始化");
            return Err("憑證取得或設定失敗".into());
        }
    };
    let ca_certificate = Certificate::from_pem(root_cert);
    let client_identity = Identity::from_pem(client_cert, client_key);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_certificate)
        .identity(client_identity);
    let channel = Endpoint::from_shared(mca_info)?
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(channel)
}
pub async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> crate::ConResult<()> {
    let svc = service_name.as_ref(); // &str
    tracing::info!("執行{svc}健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health
        .check(HealthCheckRequest {
            service: svc.into(),
        })
        .await?
        .into_inner();
    tracing::info!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
