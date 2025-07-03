use std::{collections::HashMap, error::Error, fs, io::Write, path::PathBuf, time::Duration};

use crate::{ApiResponse, ClusterClient};
use async_trait::async_trait;
use reqwest::{Client, Identity};
type ClientCert = PathBuf;
type ClientKey = PathBuf;

#[derive(Debug)]
pub struct ClientCluster {
    base_url: String,
    timeout: Duration,
    cert_chain: Option<(ClientCert, ClientKey)>,
    root_ca: Option<PathBuf>,
}

impl Default for ClientCluster {
    fn default() -> Self {
        Self {
            base_url: "localhost:50051".into(),
            timeout: Duration::from_secs(5),
            cert_chain: None,
            root_ca: None,
        }
    }
}
impl ClientCluster {
    pub fn new(
        base_url: impl Into<String>,
        cert_path: Option<impl Into<PathBuf>>,
        key_path: Option<impl Into<PathBuf>>,
        root_ca: Option<impl Into<PathBuf>>,
    ) -> Self {
        Self::default()
            .with_base_url(base_url)
            .with_cert_chain(cert_path, key_path)
            .with_root_ca(root_ca)
    }
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
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

    pub async fn build(&self) -> Result<Client, Box<dyn Error + Send + Sync>> {
        let mut builder = Client::builder().timeout(self.timeout).use_rustls_tls();
        if let Some((ref cert_p, ref key_p)) = self.cert_chain {
            let mut pem = Vec::new();
            pem.extend(fs::read(cert_p)?);
            pem.extend(fs::read(key_p)?);
            let id = Identity::from_pem(&pem)?;
            builder = builder.identity(id);
        }
        if let Some(ref ca_p) = self.root_ca {
            let ca = fs::read(ca_p)?;
            let ca_cert = reqwest::Certificate::from_pem(&ca)?;
            builder = builder.add_root_certificate(ca_cert);
        }

        Ok(builder.build()?)
    }
    pub fn get_otp(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
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
    async fn init(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.build().await?;
        tracing::info!("開始與 {} 進行通信", self.base_url);
        let otp = self.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let mut map = HashMap::new();
        map.insert("code", otp);
        let resp = client
            .post(format!("https://{}/init", self.base_url))
            .json(&map)
            .send()
            .await?;
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
