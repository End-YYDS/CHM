use std::{error::Error as StdError, fs, io::Write, path::PathBuf, sync::Arc, time::Duration};

use cached::{proc_macro::cached, TimedSizedCache};
use chm_dns_resolver::{lookup_cached, DnsResolver};
use futures::FutureExt;
use reqwest::{
    dns::{Name, Resolve, Resolving},
    Certificate, Client, Identity,
};
use tonic::transport::ClientTlsConfig;

type ClientCert = PathBuf;
type ClientKey = PathBuf;

#[derive(Debug)]
pub struct ClientCluster {
    base_url:   String,
    timeout:    Duration,
    mdns_url:   String,
    cert_chain: Option<(ClientKey, ClientCert)>,
    root_ca:    Option<PathBuf>,
    otp_code:   Option<String>,
}

impl Default for ClientCluster {
    fn default() -> Self {
        Self {
            base_url:   "localhost:50051".into(),
            timeout:    Duration::from_secs(5),
            mdns_url:   "http://127.0.0.1:50053".into(),
            cert_chain: None,
            root_ca:    None,
            otp_code:   None,
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
    Certificate::from_pem(&ca).map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)
}

impl ClientCluster {
    pub fn new(
        base_url: impl Into<String>,
        mdns_addr: Option<impl Into<String>>,
        cert_path: Option<impl Into<PathBuf>>,
        key_path: Option<impl Into<PathBuf>>,
        root_ca: Option<impl Into<PathBuf>>,
        otp_code: impl Into<Option<String>>,
    ) -> Self {
        Self::default()
            .with_mdns(mdns_addr)
            .with_base_url(base_url)
            .with_cert_chain(cert_path, key_path)
            .with_root_ca(root_ca)
            .with_otp_code(otp_code)
    }
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        // TODO: 從mDNS中解析IP地址
        self
    }
    pub fn with_mdns(mut self, mdns_addr: Option<impl Into<String>>) -> Self {
        if let Some(addr) = mdns_addr {
            let addr: String = addr.into();
            self.mdns_url = addr.clone();
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
    pub fn with_otp_code(mut self, otp: impl Into<Option<String>>) -> Self {
        self.otp_code = otp.into();
        self
    }

    pub async fn build(&self) -> Result<Client, Box<dyn StdError + Send + Sync>> {
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .use_rustls_tls()
            .danger_accept_invalid_certs(true);
        let mut tls = ClientTlsConfig::new();
        if let Some((ref key_p, ref cert_p)) = self.cert_chain {
            let id = load_client_identity(cert_p.clone(), key_p.clone())?;
            builder = builder.identity(id);
            let g_cert = tokio::fs::read(cert_p).await?;
            let g_key = tokio::fs::read(key_p).await?;
            tls = tls.identity(tonic::transport::Identity::from_pem(g_cert, g_key));
        }
        if let Some(ref ca_p) = self.root_ca {
            let ca_cert = load_ca_identity(ca_p.clone())?;
            let g_ca = tokio::fs::read(ca_p).await?;
            builder = builder.add_root_certificate(ca_cert);
            tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(g_ca));
        }
        let mini_dns = DnsResolver::new_with_result(&self.mdns_url, tls).await.ok();
        match mini_dns {
            Some(dns) => {
                tracing::debug!("成功連接到 mDNS 服務: {}", &self.mdns_url);
                let raw = Arc::new(dns);
                let my_resolver = Arc::new(MyResolver(raw));
                builder = builder.dns_resolver(my_resolver);
            }
            None => {
                tracing::warn!("無法連接到 mDNS 服務: {}, 即將跳過...", self.mdns_url);
            }
        }
        Ok(builder.build()?)
    }
    pub fn get_otp(&self) -> Result<String, Box<dyn StdError + Send + Sync>> {
        let otp = self.otp_code.clone().unwrap_or_else(|| loop {
            let mut input = String::new();
            print!("請輸入OTP code：");
            std::io::stdout().flush().expect("Can't flush stdout");
            let byte_read = std::io::stdin().read_line(&mut input).expect("Can't read from stdin");
            let otp = input.trim().trim_end_matches(['\r', '\n']);
            if byte_read == 0 || otp.is_empty() {
                println!("OTP code 不可為空，請重新輸入。");
                continue;
            } else {
                break otp.to_string();
            }
        });
        Ok(otp.to_string())
    }
    #[inline]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

pub struct MyResolver(pub Arc<DnsResolver>);
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
