use std::{
    collections::HashMap,
    error::Error as StdError,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crate::{ApiResponse, ClusterClient};
use cached::{proc_macro::cached, TimedSizedCache};
use chm_dns_resolver::{uuid::Uuid, DnsResolver};
use chm_grpc::tonic::async_trait;
use futures::FutureExt;
use reqwest::{
    dns::{Name, Resolve, Resolving},
    Certificate, Client, Identity,
};
type ClientCert = PathBuf;
type ClientKey = PathBuf;

#[derive(Debug)]
pub struct ClientCluster {
    base_url:   String,
    timeout:    Duration,
    mdns_addr:  String,
    cert_chain: Option<(ClientCert, ClientKey)>,
    root_ca:    Option<PathBuf>,
}

impl Default for ClientCluster {
    fn default() -> Self {
        Self {
            base_url:   "localhost:50051".into(),
            timeout:    Duration::from_secs(5),
            mdns_addr:  "http://127.0.0.1:50053".into(),
            cert_chain: None,
            root_ca:    None,
        }
    }
}

#[cached(
    name = "LOAD_CLIENT_IDENTITY_CACHE",
    ty = "TimedSizedCache<(PathBuf, PathBuf), Identity>",
    create = "{ TimedSizedCache::with_size_and_lifespan(4, Duration::from_secs(600)) }",
    convert = r#"{ (cert_path.clone(), key_path.clone()) }"#,
    result = true
)]
fn load_client_identity(
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<Identity, Box<dyn StdError + Send + Sync>> {
    let mut pem = Vec::new();
    pem.extend(fs::read(cert_path)?);
    pem.extend(fs::read(key_path)?);
    Identity::from_pem(&pem).map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)
}
#[cached(
    name = "LOAD_CA_IDENTITY_CACHE",
    ty = "TimedSizedCache<PathBuf, Certificate>",
    create = "{ TimedSizedCache::with_size_and_lifespan(4, Duration::from_secs(600)) }",
    convert = r#"{ ca_p.clone() }"#,
    result = true
)]
fn load_ca_identity(ca_p: PathBuf) -> Result<Certificate, Box<dyn StdError + Send + Sync>> {
    let ca = fs::read(ca_p)?;
    reqwest::Certificate::from_pem(&ca).map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)
}

impl ClientCluster {
    pub fn new(
        base_url: impl Into<String>,
        mdns_addr: Option<impl Into<String>>,
        cert_path: Option<impl Into<PathBuf>>,
        key_path: Option<impl Into<PathBuf>>,
        root_ca: Option<impl Into<PathBuf>>,
    ) -> Self {
        Self::default()
            .with_mdns(mdns_addr)
            .with_base_url(base_url)
            .with_cert_chain(cert_path, key_path)
            .with_root_ca(root_ca)
    }
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        // TODO: 從mDNS中解析IP地址
        self
    }
    pub fn with_mdns(mut self, mdns_addr: Option<impl Into<String>>) -> Self {
        if let Some(addr) = mdns_addr {
            let addr: String = addr.into();
            self.mdns_addr = addr.clone();
        }
        self
    }
    pub fn with_cert_chain(
        mut self,
        cert_path: Option<impl Into<PathBuf>>,
        key_path: Option<impl Into<PathBuf>>,
    ) -> Self {
        self.cert_chain = match (cert_path, key_path) {
            (Some(cert), Some(key)) => Some((cert.into(), key.into())),
            _ => None,
        };
        self
    }

    pub fn with_root_ca(mut self, ca_path: Option<impl Into<PathBuf>>) -> Self {
        self.root_ca = ca_path.map(Into::into);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn build(&self) -> Result<Client, Box<dyn StdError + Send + Sync>> {
        let raw = Arc::new(DnsResolver::new(&self.mdns_addr).await);
        let my_resolver = Arc::new(MyResolver(raw));
        let mut builder =
            Client::builder().dns_resolver(my_resolver).timeout(self.timeout).use_rustls_tls();
        if let Some((ref cert_p, ref key_p)) = self.cert_chain {
            let id = load_client_identity(cert_p.clone(), key_p.clone())?;
            builder = builder.identity(id);
        }
        if let Some(ref ca_p) = self.root_ca {
            let ca_cert = load_ca_identity(ca_p.clone())?;
            builder = builder.add_root_certificate(ca_cert);
        }

        Ok(builder.build()?)
    }
    pub fn get_otp(&self) -> Result<String, Box<dyn StdError + Send + Sync>> {
        let mut input = String::new();
        print!("請輸入OTP code：");
        std::io::stdout().flush()?;
        let byte_read = std::io::stdin().read_line(&mut input)?;
        let otp = input.trim().trim_end_matches(['\r', '\n']);
        if byte_read == 0 || otp.is_empty() {
            return Err("未輸入OTP，請重新啟動並輸入OTP".into());
        }
        Ok(otp.to_string())
    }
}

#[async_trait]
impl ClusterClient for ClientCluster {
    async fn init(&mut self) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let client = self.build().await?;
        tracing::info!("開始與 {} 進行通信", self.base_url);
        let otp = self.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let mut map = HashMap::new();
        map.insert("code", otp);
        let url = format!("{}/init", self.base_url);
        tracing::debug!("初始化請求 URL: {}", url);
        // TODO: 檢查是否為UUID是就解析成hostname之後
        let resp = client.post(url).json(&map).send().await?;
        let api_resp: ApiResponse = resp.json().await?;
        if !api_resp.ok {
            let err_msg = api_resp.message.clone();
            tracing::error!("初始化失敗: {}", err_msg);
            return Err(err_msg.into());
        }

        println!("{api_resp:#?}");
        Ok(())
    }
}

pub struct MyResolver(pub Arc<DnsResolver>);
async fn lookup_host_or_custom_uncached(
    resolver: &DnsResolver,
    host: &str,
) -> Result<SocketAddr, Box<dyn StdError + Send + Sync>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 0));
    }
    if let Ok(uid) = Uuid::parse_str(host) {
        let ip_str = resolver.get_ip_by_uuid(uid).await?;
        let ip = ip_str.parse()?;
        return Ok(SocketAddr::new(ip, 0));
    }
    let ip_str = resolver.get_ip_by_hostname(host).await?;
    let ip = ip_str.parse()?;
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
async fn lookup_cached(
    resolver: Arc<DnsResolver>,
    host: String,
) -> Result<SocketAddr, Box<dyn StdError + Send + Sync>> {
    lookup_host_or_custom_uncached(&resolver, &host).await
}

impl Resolve for MyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let resolver = Arc::clone(&self.0);
        async move {
            let addr = lookup_cached(resolver, host).await?;
            Ok(Box::new(std::iter::once(addr)) as _)
        }
        .boxed()
    }
}
