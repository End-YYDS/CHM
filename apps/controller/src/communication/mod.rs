#![allow(dead_code)]

use crate::{ConResult, GlobalConfig};
use backoff::{future::retry, ExponentialBackoff};
use chm_grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};
use futures::future::try_join_all;
use std::{collections::HashMap, time::Duration};

pub(crate) mod ca;
pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod ldap;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct GrpcClients {
    pub ca: ca::ClientCA,
    // Todo: 其他服務的客戶端可以在這裡添加
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    Mca,
    Dns,
    Ldap,
    Dhcp,
}
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub kind:        ServiceKind,
    pub uri:         String,
    pub health_name: Option<&'static str>,
    pub log_name:    &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct GrpcConnectOptions {
    pub connect_timeout: Option<Duration>,
    pub overall_timeout: Option<Duration>,
    pub tcp_keepalive:   Option<Duration>,
    pub tcp_nodelay:     Option<bool>,

    pub h2_keepalive_interval: Option<Duration>,
    pub keep_alive_timeout:    Option<Duration>,
    pub keep_alive_while_idle: Option<bool>,
    pub http2_adaptive_window: Option<bool>,

    pub concurrency_limit:          Option<usize>,
    pub initial_conn_window_size:   Option<u32>,
    pub initial_stream_window_size: Option<u32>,
}

impl GrpcConnectOptions {
    #[inline]
    pub fn builder() -> GrpcConnectOptionsBuilder {
        GrpcConnectOptionsBuilder::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct GrpcConnectOptionsBuilder {
    inner: GrpcConnectOptions,
}
impl GrpcConnectOptionsBuilder {
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.inner.connect_timeout = Some(d);
        self
    }
    pub fn overall_timeout(mut self, d: Duration) -> Self {
        self.inner.overall_timeout = Some(d);
        self
    }
    pub fn tcp_keepalive(mut self, d: Duration) -> Self {
        self.inner.tcp_keepalive = Some(d);
        self
    }
    pub fn tcp_nodelay(mut self, on: bool) -> Self {
        self.inner.tcp_nodelay = Some(on);
        self
    }

    pub fn h2_keepalive_interval(mut self, d: Duration) -> Self {
        self.inner.h2_keepalive_interval = Some(d);
        self
    }
    pub fn keep_alive_timeout(mut self, d: Duration) -> Self {
        self.inner.keep_alive_timeout = Some(d);
        self
    }
    pub fn keep_alive_while_idle(mut self, on: bool) -> Self {
        self.inner.keep_alive_while_idle = Some(on);
        self
    }
    pub fn http2_adaptive_window(mut self, on: bool) -> Self {
        self.inner.http2_adaptive_window = Some(on);
        self
    }

    pub fn concurrency_limit(mut self, n: usize) -> Self {
        self.inner.concurrency_limit = Some(n);
        self
    }
    pub fn initial_conn_window_size(mut self, bytes: u32) -> Self {
        self.inner.initial_conn_window_size = Some(bytes);
        self
    }
    pub fn initial_stream_window_size(mut self, bytes: u32) -> Self {
        self.inner.initial_stream_window_size = Some(bytes);
        self
    }
    pub fn build(self) -> GrpcConnectOptions {
        self.inner
    }
}

pub async fn grpc_connect_with_retry(
    uri: &str,
    tls: ClientTlsConfig,
    backoff: ExponentialBackoff,
    opts: &GrpcConnectOptions,
    log_name: &str,
) -> ConResult<Channel> {
    let mut endpoint = Endpoint::from_shared(uri.to_string())?.tls_config(tls)?;

    if let Some(d) = opts.connect_timeout {
        endpoint = endpoint.connect_timeout(d);
    }
    if let Some(d) = opts.overall_timeout {
        endpoint = endpoint.timeout(d);
    }
    if let Some(d) = opts.tcp_keepalive {
        endpoint = endpoint.tcp_keepalive(Some(d));
    }
    if let Some(on) = opts.tcp_nodelay {
        endpoint = endpoint.tcp_nodelay(on);
    }
    if let Some(d) = opts.h2_keepalive_interval {
        endpoint = endpoint.http2_keep_alive_interval(d);
    }
    if let Some(d) = opts.keep_alive_timeout {
        endpoint = endpoint.keep_alive_timeout(d);
    }
    if let Some(on) = opts.keep_alive_while_idle {
        endpoint = endpoint.keep_alive_while_idle(on);
    }
    if let Some(on) = opts.http2_adaptive_window {
        endpoint = endpoint.http2_adaptive_window(on);
    }
    if let Some(n) = opts.concurrency_limit {
        endpoint = endpoint.concurrency_limit(n);
    }
    if let Some(bytes) = opts.initial_conn_window_size {
        endpoint = endpoint.initial_connection_window_size(bytes);
    }
    if let Some(bytes) = opts.initial_stream_window_size {
        endpoint = endpoint.initial_stream_window_size(bytes);
    }

    tracing::debug!("初始化 {log_name} gRPC 連線（帶重試）…");
    let channel = retry(backoff, || async {
        match endpoint.clone().connect().await {
            Ok(ch) => {
                tracing::info!("{log_name} gRPC Channel 已建立");
                Ok(ch)
            }
            Err(e) => {
                tracing::warn!("{log_name} 連線失敗：{e}，稍後重試…");
                Err(backoff::Error::transient(e))
            }
        }
    })
    .await?;
    Ok(channel)
}
pub async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> ConResult<()> {
    let svc = service_name.as_ref();
    tracing::info!("執行{svc}健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health.check(HealthCheckRequest { service: svc.into() }).await?.into_inner();
    tracing::info!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
pub async fn connect_all_services(
    services: &[ServiceDescriptor],
    tls: ClientTlsConfig,
    backoff: ExponentialBackoff,
    opts: &GrpcConnectOptions,
) -> ConResult<HashMap<ServiceKind, Channel>> {
    let futs = services.iter().map(|svc| {
        let tls = tls.clone();
        let opts = opts.clone();
        let backoff = backoff.clone();
        async move {
            let ch = grpc_connect_with_retry(&svc.uri, tls, backoff, &opts, svc.log_name).await?;
            if let Some(health_name) = svc.health_name {
                health_check(ch.clone(), health_name).await?;
            } else {
                tracing::info!("{} 跳過健康檢查", svc.log_name);
            }
            ConResult::<(ServiceKind, Channel)>::Ok((svc.kind, ch))
        }
    });
    let pairs: Vec<(ServiceKind, Channel)> = try_join_all(futs).await?;
    Ok(pairs.into_iter().collect())
}

pub async fn init_channels_all() -> ConResult<GrpcClients> {
    let (root_cert, client_cert, client_key, mca_uri) =
        GlobalConfig::with(|cfg| -> ConResult<_> {
            let root = &cfg.certificate.root_ca;
            let cert = &cfg.certificate.client_cert;
            let key = &cfg.certificate.client_key;
            let mca = &cfg.extend.server_ext.ca_server;
            if root.as_os_str().is_empty()
                || cert.as_os_str().is_empty()
                || key.as_os_str().is_empty()
                || mca.is_empty()
            {
                return Err("GlobalsVar 中的憑證或 URI 未正確初始化".into());
            }
            let root_bytes = std::fs::read(root).map_err(|_| "無法讀取 CA 根憑證")?;
            let cert_bytes = std::fs::read(cert).map_err(|_| "無法讀取客戶端憑證")?;
            let key_bytes = std::fs::read(key).map_err(|_| "無法讀取客戶端金鑰")?;
            Ok((root_bytes, cert_bytes, key_bytes, mca.clone()))
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

    let services = vec![ServiceDescriptor {
        kind:        ServiceKind::Mca,
        uri:         mca_uri,
        health_name: Some("ca.CA"),
        log_name:    "CA",
    }];
    let channels = connect_all_services(&services, tls, backoff, &opts).await?;
    let ca_client = ca::ClientCA::new(channels[&ServiceKind::Mca].clone());
    // let dns_client = dns::ClientDNS::new(channels[&ServiceKind::Dns].clone());
    // let ldap_client =
    // ldap::ClientLdap::new(channels[&ServiceKind::Ldap].clone());
    // let dhcp_client =
    // dhcp::ClientDhcp::new(channels[&ServiceKind::Dhcp].clone());

    Ok(GrpcClients { ca: ca_client })
}
