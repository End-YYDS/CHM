use crate::{ConResult, GlobalConfig};
use chm_grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};
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
pub async fn ca_grpc_connection_init() -> ConResult<Channel> {
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

        (root.clone(), cert.clone(), key.clone(), ca.clone())
    };
    let ca_certificate = Certificate::from_pem(root_cert);
    let client_identity = Identity::from_pem(client_cert, client_key);
    let tls = ClientTlsConfig::new().ca_certificate(ca_certificate).identity(client_identity);
    let channel = Endpoint::from_shared(mca_info)?.tls_config(tls)?.connect().await?;
    Ok(channel)
}
pub async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> crate::ConResult<()> {
    let svc = service_name.as_ref(); // &str
    tracing::info!("執行{svc}健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health.check(HealthCheckRequest { service: svc.into() }).await?.into_inner();
    tracing::info!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
