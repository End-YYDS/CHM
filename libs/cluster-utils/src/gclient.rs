use backoff::{future::retry, ExponentialBackoff};
use chm_dns_resolver::{lookup_cached, DnsResolver};
use chm_grpc::tonic_health::pb::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
};
use hyper_util::rt::TokioIo;
use serde::de::StdError;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tower::{service_fn, util::BoxCloneService};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type RetryErr = backoff::Error<Box<dyn StdError + Send + Sync>>;
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

fn to_io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(format!("{e}"))
}
// fn make_minidns_connector(
//     resolver: Arc<DnsResolver>,
// ) -> impl tower::Service<
//     Uri,
//     Response = TokioIo<TcpStream>,
//     Error = io::Error,
//     Future = impl Future<Output = std::result::Result<TokioIo<TcpStream>,
// io::Error>> + Send,
// > + Clone { service_fn(move |uri: Uri| { let resolver = resolver.clone();
// > async move { let host = uri .host() .ok_or_else(||
// > io::Error::new(io::ErrorKind::InvalidInput, "URI 缺少 host"))?
// > .to_string(); let cached = lookup_cached(resolver,
// > host).await.map_err(to_io_err)?; let port =
// > uri.port_u16().unwrap_or_else(|| match uri.scheme_str() { Some("https") =>
// > 443, _ => 80, }); let target = SocketAddr::new(cached.ip(), port); let
// > stream = TcpStream::connect(target).await?; Ok(TokioIo::new(stream)) } })
// }
// fn make_default_connector() -> impl tower::Service<
//     Uri,
//     Response = TokioIo<TcpStream>,
//     Error = io::Error,
//     Future = impl Future<Output = std::result::Result<TokioIo<TcpStream>,
// io::Error>> + Send,
// > + Clone { service_fn(move |uri: Uri| async move { let host = uri .host()
// > .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URI 缺少
// > host"))? .to_string(); let port = uri.port_u16().unwrap_or_else(|| match
// > uri.scheme_str() { Some("https") => 443, _ => 80, }); let stream =
// > TcpStream::connect((host.as_str(), port)).await?; Ok(TokioIo::new(stream))
// > })
// }

fn make_minidns_connector(
    resolver: Arc<DnsResolver>,
) -> BoxCloneService<Uri, TokioIo<TcpStream>, io::Error> {
    BoxCloneService::new(service_fn(move |uri: Uri| {
        let resolver = resolver.clone();
        async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URI 缺少 host"))?
                .to_string();

            let cached = lookup_cached(resolver, host).await.map_err(to_io_err)?;
            let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });

            let target = SocketAddr::new(cached.ip(), port);
            let stream = TcpStream::connect(target).await?;
            Ok::<_, io::Error>(TokioIo::new(stream))
        }
    }))
}

fn make_default_connector() -> BoxCloneService<Uri, TokioIo<TcpStream>, io::Error> {
    BoxCloneService::new(service_fn(move |uri: Uri| async move {
        let host = uri
            .host()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URI 缺少 host"))?
            .to_string();

        let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });

        let stream = TcpStream::connect((host.as_str(), port)).await?;
        Ok::<_, io::Error>(TokioIo::new(stream))
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn grpc_connect_with_retry(
    uri: &str,
    mut tls: ClientTlsConfig,
    backoff: ExponentialBackoff,
    opts: &GrpcConnectOptions,
    log_name: &str,
    minidns: Option<Arc<DnsResolver>>,
    sni_override: Option<&str>,
    gservice_name: Option<&str>,
) -> Result<Channel> {
    if let Some(sni) = sni_override {
        tls = tls.domain_name(sni);
    }
    let connector: BoxCloneService<Uri, TokioIo<TcpStream>, io::Error> = match minidns {
        Some(resolver) => make_minidns_connector(resolver),
        None => make_default_connector(),
    };
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
    let channel = retry(backoff.clone(), || async {
        match endpoint.clone().connect_with_connector(connector.clone()).await {
            Ok(ch) => {
                tracing::debug!("{log_name} gRPC Channel 已建立");
                Ok(ch)
            }
            Err(e) => {
                tracing::warn!("{log_name} 連線失敗：{e}，稍後重試…");
                tracing::debug!(error = ?e, "{log_name} 連線錯誤詳情");
                Err(backoff::Error::transient(e))
            }
        }
    })
    .await?;
    retry(backoff, || {
        let mut health = HealthClient::new(channel.clone());
        let service_name: String = gservice_name.unwrap_or("").to_owned();
        async move {
            match health.check(HealthCheckRequest { service: service_name.clone() }).await {
                Ok(resp) => {
                    let status = resp.into_inner().status;
                    if status == ServingStatus::Serving as i32 {
                        tracing::info!("Health 狀態為 Serving");
                        Ok(())
                    } else {
                        tracing::warn!("Health 非 Serving (status={status})，將重試…");
                        Err(RetryErr::transient(io::Error::other("Health 非 Serving").into()))
                    }
                }
                Err(e) => {
                    tracing::warn!("Health 呼叫失敗：{e}，將重試…");
                    Err(RetryErr::transient(e.into()))
                }
            }
        }
    })
    .await?;
    Ok(channel)
}
