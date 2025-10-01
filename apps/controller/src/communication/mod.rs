use crate::{ClientMap, ConResult, GlobalConfig};
use backoff::ExponentialBackoff;
use chm_cluster_utils::{
    gclient::{grpc_connect_with_retry, GrpcConnectOptions},
    ServiceDescriptor, ServiceKind,
};
use chm_dns_resolver::DnsResolver;
use chm_grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};
use futures::future::try_join_all;
use std::{collections::HashMap, sync::Arc, time::Duration};

pub(crate) mod ca;
pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod ldap;

#[derive(Debug, Clone)]
pub enum ClientHandle {
    Ca(ca::ClientCA),
    // Dns(dns::ClientDNS),
    // Ldap(ldap::ClientLdap),
    // Dhcp(dhcp::ClientDhcp),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct GrpcClients {
    pub map: ClientMap,
}

impl GrpcClients {
    pub async fn connect_all() -> ConResult<Self> {
        init_channels_all().await
    }
    pub fn ca(&self) -> Option<&ca::ClientCA> {
        match self.map.get(&ServiceKind::Mca) {
            Some(ClientHandle::Ca(ca)) => Some(ca),
            _ => None,
        }
    }
}

pub async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> ConResult<()> {
    let svc = service_name.as_ref();
    tracing::debug!("執行 {svc} 健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health.check(HealthCheckRequest { service: svc.into() }).await?.into_inner();
    tracing::debug!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
pub async fn connect_all_services(
    services: &[ServiceDescriptor],
    tls: ClientTlsConfig,
    backoff: ExponentialBackoff,
    opts: &GrpcConnectOptions,
) -> ConResult<HashMap<ServiceKind, Channel>> {
    let mdns_addr = GlobalConfig::with(|cfg| cfg.server.dns_server.clone());
    let dns_rosolver = Arc::new(DnsResolver::new(mdns_addr).await);
    let futs = services.iter().map(|svc| {
        let minidns = dns_rosolver.clone();
        let tls = tls.clone();
        let opts = opts.clone();
        let backoff = backoff.clone();
        async move {
            let ch = grpc_connect_with_retry(
                &svc.uri,
                tls,
                backoff,
                &opts,
                &svc.hostname,
                minidns,
                None,
            )
            .await?;
            if let Some(health_name) = svc.health_name.as_deref() {
                health_check(ch.clone(), health_name).await?;
            } else {
                tracing::info!("{} 跳過健康檢查", svc.hostname);
            }
            ConResult::<(ServiceKind, Channel)>::Ok((svc.kind, ch))
        }
    });
    let pairs: Vec<(ServiceKind, Channel)> = try_join_all(futs).await?;
    Ok(pairs.into_iter().collect())
}

pub async fn init_channels_all() -> ConResult<GrpcClients> {
    let (root_cert, client_cert, client_key) = GlobalConfig::with(|cfg| -> ConResult<_> {
        let root = &cfg.certificate.root_ca;
        let cert = &cfg.certificate.client_cert;
        let key = &cfg.certificate.client_key;
        if root.as_os_str().is_empty() || cert.as_os_str().is_empty() || key.as_os_str().is_empty()
        {
            return Err("GlobalsVar 中的憑證或 URI 未正確初始化".into());
        }
        let root_bytes = std::fs::read(root).map_err(|_| "無法讀取 CA 根憑證")?;
        let cert_bytes = std::fs::read(cert).map_err(|_| "無法讀取客戶端憑證")?;
        let key_bytes = std::fs::read(key).map_err(|_| "無法讀取客戶端金鑰")?;
        Ok((root_bytes, cert_bytes, key_bytes))
    })?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(root_cert))
        .identity(Identity::from_pem(client_cert, client_key));
    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    let opts = GrpcConnectOptions::builder()
        .connect_timeout(Duration::from_secs(5))
        .overall_timeout(Duration::from_secs(20))
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        .h2_keepalive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .http2_adaptive_window(true)
        .concurrency_limit(256)
        .initial_conn_window_size(2_097_152)
        .initial_stream_window_size(1_048_576)
        .build();
    let services: Vec<ServiceDescriptor> = GlobalConfig::with(|cfg| {
        cfg.extend
            .services_pool
            .services
            .iter()
            .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
            .collect()
    });
    let channels = connect_all_services(&services, tls, backoff, &opts).await?;
    let client_map: ClientMap = crate::build_clients!(
        &channels, {
            Mca  => Ca(ca::ClientCA::new)
            // Dns  => Dns(dns::ClientDNS::new),
            // Ldap => Ldap(ldap::ClientLdap::new),
            // Dhcp => Dhcp(dhcp::ClientDhcp::new),
        }
    );
    Ok(GrpcClients { map: client_map })
}
