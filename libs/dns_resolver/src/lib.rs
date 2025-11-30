use backoff::{future::retry, ExponentialBackoff};
use cached::proc_macro::cached;
use chm_grpc::{
    dns::dns_service_client::DnsServiceClient,
    tonic::transport::{Channel, ClientTlsConfig, Endpoint},
    tonic_health::pb::{
        health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    },
};
use std::{
    error::Error as StdError,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use url::{Host, Url};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn StdError + Send + Sync>>;
type RetryErr = backoff::Error<Box<dyn StdError + Send + Sync>>;
const DNS_SERVICE_FQN: &str = "dns.DnsService";
#[derive(Debug)]
pub struct DnsResolver {
    dns_address: String,
    client:      DnsServiceClient<Channel>,
}
pub enum DnsQuery {
    Hostname(String),
    Uuid(Uuid),
}
impl From<String> for DnsQuery {
    fn from(s: String) -> Self {
        DnsQuery::Hostname(s)
    }
}

impl From<&String> for DnsQuery {
    fn from(s: &String) -> Self {
        DnsQuery::Hostname(s.clone())
    }
}

impl From<&str> for DnsQuery {
    fn from(s: &str) -> Self {
        DnsQuery::Hostname(s.to_string())
    }
}

impl From<Uuid> for DnsQuery {
    fn from(u: Uuid) -> Self {
        DnsQuery::Uuid(u)
    }
}
impl DnsResolver {
    fn default_backoff(max_time: Duration) -> ExponentialBackoff {
        ExponentialBackoff { max_elapsed_time: Some(max_time), ..Default::default() }
    }

    async fn connect_channel_with_backoff(
        dns_address: &str,
        max_time: Duration,
        tls: ClientTlsConfig,
    ) -> Result<Channel> {
        let backoff = Self::default_backoff(max_time);
        let addr = dns_address.to_owned();
        let tls_cfg = tls.clone();
        let channel: Channel = retry(backoff, move || {
            let addr = addr.clone();
            let tls_cfg = tls_cfg.clone();
            async move {
                tracing::debug!("嘗試建立 gRPC channel: {addr}");
                let mut ep = Endpoint::from_shared(addr.clone())
                    .map_err(|e| RetryErr::transient(e.into()))?;
                let needs_tls = addr.starts_with("https://");
                if needs_tls {
                    ep = ep.tls_config(tls_cfg).map_err(|e| RetryErr::transient(e.into()))?;
                }

                match ep.connect().await {
                    Ok(ch) => {
                        tracing::debug!("成功建立 gRPC channel: {addr}");
                        Ok(ch)
                    }
                    Err(e) => {
                        tracing::warn!("建立 channel 失敗: {e}，將重試…");
                        tracing::debug!(error = ?e, "建立 gRPC channel 錯誤詳情");
                        Err(RetryErr::transient(e.into()))
                    }
                }
            }
        })
        .await?;

        Ok(channel)
    }
    async fn wait_health_serving_with_backoff(
        channel: Channel,
        service_name: &str,
        max_time: Duration,
    ) -> Result<Channel> {
        let backoff = Self::default_backoff(max_time);

        retry(backoff, || {
            let mut health = HealthClient::new(channel.clone());
            let service_name = service_name.to_string();
            async move {
                match health.check(HealthCheckRequest { service: service_name.clone() }).await {
                    Ok(resp) => {
                        let status = resp.into_inner().status;
                        if status == ServingStatus::Serving as i32 {
                            tracing::info!("Health 狀態為 Serving");
                            Ok(())
                        } else {
                            tracing::warn!(
                                "Health 非 Serving
    (status={status})，將重試…"
                            );
                            Err(RetryErr::transient(
                                std::io::Error::other("Health 非 Serving").into(),
                            ))
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

    async fn connect_with_backoff(
        dns_address: &str,
        max_time: Duration,
        tls: ClientTlsConfig,
    ) -> Result<DnsServiceClient<Channel>> {
        let channel = Self::connect_channel_with_backoff(dns_address, max_time, tls).await?;
        let channel =
            Self::wait_health_serving_with_backoff(channel, DNS_SERVICE_FQN, max_time).await?;
        Ok(DnsServiceClient::new(channel))
    }

    pub async fn new(dns_address: impl Into<String>, tls: ClientTlsConfig) -> Self {
        let dns_address = dns_address.into();
        let client = Self::connect_with_backoff(&dns_address, Duration::from_secs(5), tls)
            .await
            .expect("重試後仍無法連上 DNS service，是否初始化過?");
        Self { dns_address, client }
    }

    pub async fn new_with_result(
        dns_address: impl Into<String>,
        tls: ClientTlsConfig,
    ) -> Result<Self> {
        let dns_address = dns_address.into();
        let client = Self::connect_with_backoff(&dns_address, Duration::from_secs(5), tls).await?;
        Ok(Self { dns_address, client })
    }

    pub async fn resolve_ip<Q>(&self, query: Q) -> Result<String>
    where
        Q: Into<DnsQuery>,
    {
        let s = match query.into() {
            DnsQuery::Uuid(u) => return self.get_ip_by_uuid(u).await,
            DnsQuery::Hostname(s) => s,
        };
        if let Ok(url) = Url::parse(&s) {
            let scheme = url.scheme();
            if scheme == "http" || scheme == "https" {
                if let Some(host_str) = url.host_str() {
                    let port = url.port_or_known_default().unwrap();
                    let ip_addr = if host_str.parse::<Ipv4Addr>().is_ok() {
                        host_str.to_string()
                    } else if let Ok(uuid) = Uuid::parse_str(host_str) {
                        self.get_ip_by_uuid(uuid).await?
                    } else {
                        self.get_ip_by_hostname(host_str).await?
                    };
                    return Ok(format!("{scheme}://{ip_addr}:{port}"));
                }
            }
        }
        if let Ok(uuid) = Self::get_uuid_from_url(&s) {
            return self.get_ip_by_uuid(uuid).await;
        }
        if let Ok(ipv4) = Self::get_ipv4_from_url(&s) {
            return Ok(ipv4.to_string());
        }
        if let Ok(domain) = Self::get_hostname_from_url(&s) {
            return self.get_ip_by_hostname(&domain).await;
        }
        if let Ok(uuid) = Uuid::parse_str(&s) {
            return self.get_ip_by_uuid(uuid).await;
        }
        if s.parse::<Ipv4Addr>().is_ok() {
            return Ok(s);
        }
        self.get_ip_by_hostname(&s).await
    }
    pub fn get_dns_address(&self) -> &str {
        &self.dns_address
    }
    pub async fn get_ip_by_hostname(&self, hostname: &str) -> Result<String> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetIpByHostnameRequest { hostname: hostname.to_string() };
        let response = client.get_ip_by_hostname(request).await?.into_inner();
        Ok(response.ip)
    }
    pub async fn get_ip_by_uuid(&self, uid: Uuid) -> Result<String> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetIpByUuidRequest { id: uid.to_string() };
        let response = client.get_ip_by_uuid(request).await?.into_inner();
        Ok(response.ip)
    }
    pub async fn get_hostname_by_ip(&self, ip: &str) -> Result<String> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetHostnameByIpRequest { ip: ip.to_string() };
        let response = client.get_hostname_by_ip(request).await?.into_inner();
        Ok(response.hostname)
    }
    pub async fn get_hostname_by_uuid(&self, uid: Uuid) -> Result<String> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetHostnameByUuidRequest { id: uid.to_string() };
        let response = client.get_hostname_by_uuid(request).await?.into_inner();
        Ok(response.hostname)
    }
    pub async fn get_uuid_by_ip(&self, ip: &str) -> Result<Uuid> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetUuidByIpRequest { ip: ip.to_string() };
        let response = client.get_uuid_by_ip(request).await?.into_inner();
        Ok(Uuid::parse_str(&response.id)?)
    }
    pub async fn get_uuid_by_hostname(&self, hostname: &str) -> Result<Uuid> {
        let mut client = self.client.clone();
        let request = chm_grpc::dns::GetUuidByHostnameRequest { hostname: hostname.to_string() };
        let response = client.get_uuid_by_hostname(request).await?.into_inner();
        Ok(Uuid::parse_str(&response.id)?)
    }
    pub fn is_ipv4(s: &str) -> bool {
        s.parse::<Ipv4Addr>().is_ok()
    }
    pub fn is_http_ipv4_url(s: &str) -> bool {
        let url = match Url::parse(s) {
            Ok(u) => u,
            Err(_) => return false,
        };
        match url.scheme() {
            "http" | "https" => {}
            _ => return false,
        }
        matches!(url.host(), Some(Host::Ipv4(_)))
    }
    pub fn get_ipv4_from_url(s: &str) -> Result<Ipv4Addr> {
        let url = Url::parse(s)?;
        match url.host() {
            Some(Host::Ipv4(ip)) => Ok(ip),
            _ => Err("URL does not contain a valid IPv4 address".into()),
        }
    }
    pub fn get_hostname_from_url(s: &str) -> Result<String> {
        let url = Url::parse(s)?;
        match url.host() {
            Some(Host::Domain(hostname)) => Ok(hostname.to_string()),
            _ => Err("URL does not contain a valid hostname".into()),
        }
    }
    pub fn get_uuid_from_url(s: &str) -> Result<Uuid> {
        let url = Url::parse(s)?;
        if let Some(host) = url.host_str() {
            if let Ok(u) = Uuid::parse_str(host) {
                return Ok(u);
            }
        }
        if let Some(segments) = url.path_segments() {
            for seg in segments {
                if let Ok(u) = Uuid::parse_str(seg) {
                    return Ok(u);
                }
            }
        }
        Err("URL does not contain a valid UUID".into())
    }
    pub fn get_local_ip() -> Result<IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        if local_addr.ip().is_ipv4() {
            Ok(local_addr.ip())
        } else {
            Err("Local address is not an IPv4 address".into())
        }
    }
}

pub async fn lookup_host_via_minidns(
    resolver: &DnsResolver,
    host: &str,
) -> std::result::Result<SocketAddr, Box<dyn StdError + Send + Sync>> {
    let ip_str = resolver.resolve_ip(host).await?;
    let ip: IpAddr = ip_str.parse()?;
    Ok(SocketAddr::new(ip, 0))
}

#[cached(
    name = "DNS_CACHE",
    time = 60,
    key = "String",
    convert = r#"{ host.clone() }"#,
    size = 100,
    result = true
)]
pub async fn lookup_cached(
    resolver: Arc<DnsResolver>,
    host: String,
) -> std::result::Result<SocketAddr, Box<dyn StdError + Send + Sync>> {
    lookup_host_via_minidns(&resolver, &host).await
}

pub fn get_local_hostname() -> Result<String> {
    let hostname = hostname::get()?;
    let hostname_str = hostname.into_string().map_err(|_| "無法將主機名稱轉換為字串")?;
    Ok(hostname_str)
}
