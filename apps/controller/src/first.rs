use std::path::PathBuf;

use crate::ConResult;
use cert_utils::CertUtils;
use cluster_utils::{ClusterClient, Default_ClientCluster};
use grpc::tonic::async_trait;
type Key = Vec<u8>;
type Cert = Vec<u8>;

struct FirstStart {
    base_url: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    root_ca: PathBuf,
    inner: Default_ClientCluster,
}
impl FirstStart {
    pub fn new(
        base_url: impl Into<String>,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        root_ca: impl Into<PathBuf>,
    ) -> Self {
        let base_url: String = base_url.into();
        let cert_path: PathBuf = cert_path.into();
        let key_path: PathBuf = key_path.into();
        let root_ca: PathBuf = root_ca.into();
        Self {
            base_url: base_url.clone(),
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            root_ca: root_ca.clone(),
            inner: Default_ClientCluster::new(base_url, cert_path, key_path, root_ca),
        }
    }
}

#[async_trait]
impl ClusterClient for FirstStart {
    async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.inner.build().await?;
        tracing::info!("開始與 {} 進行通信", self.base_url);
        let otp = self.inner.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let mut map = std::collections::HashMap::new();
        map.insert("code", otp);
        let resp = client
            .post(format!("{}/init", self.base_url))
            .json(&map)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            tracing::error!("初始化失敗，狀態碼：{}", status);
            return Err(format!("初始化失敗，狀態碼：{status}").into());
        }
        let body: String = resp.text_with_charset("utf-8").await?;
        tracing::info!("初始化成功，狀態碼：{}\n內容: {}", status, body);
        Ok(())
    }
}

pub async fn first_run() -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    // let (key, cert): (Key, Cert) = CertUtils::generate_csr(
    //     4096,
    //     "TW",
    //     "Taipei",
    //     "Taipei",
    //     "CHM Organization",
    //     "controller.chm.com",
    //     &["127.0.0.1", "localhost"],
    // )?;
    let (key, cert): (Key, Cert) = CertUtils::generate_self_signed_cert(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "controller.chm.com",
        &["127.0.0.1", "localhost"],
        1,
    )?;
    CertUtils::save_cert("controller", key, cert)?;
    tracing::info!("憑證已生成，請檢查 controller.pem 和 controller.key");

    // std::fs::write(&marker_path, "done")?;
    Ok(())
}
