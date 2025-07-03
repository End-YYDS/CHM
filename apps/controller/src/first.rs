use std::path::{Path, PathBuf};

use crate::ConResult;
use cert_utils::CertUtils;
use cluster_utils::{ClusterClient, Default_ClientCluster};
use grpc::tonic::async_trait;
use project_const::ProjectConst;
use serde::{Deserialize, Serialize};

struct FirstStart {
    base_url: String,
    private_key: Vec<u8>,
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<Vec<u8>>>,
    inner: Default_ClientCluster,
}
impl FirstStart {
    pub fn new(base_url: impl Into<String>, private_key: Vec<u8>, cert: Option<Vec<u8>>) -> Self {
        let base_url: String = base_url.into();
        Self {
            base_url: base_url.clone(),
            private_key,
            cert,
            cert_chain: None,
            inner: Default_ClientCluster::new(
                base_url,
                None::<PathBuf>,
                None::<PathBuf>,
                None::<PathBuf>,
            ),
        }
    }
    pub fn set_cert(&mut self, cert: Vec<u8>) {
        self.cert = Some(cert);
    }
    pub fn set_cert_chain(&mut self, cert_chain: Vec<Vec<u8>>) {
        self.cert_chain = Some(cert_chain);
    }
}

#[derive(Debug, Deserialize)]
struct SignedCertResponse {
    cert: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
struct Otp {
    code: String,
    csr_cert: Vec<u8>,
    days: u32,
}

#[async_trait]
impl ClusterClient for FirstStart {
    async fn init(&mut self) -> ConResult<()> {
        let client = self.inner.build().await?;
        tracing::info!("開始與 {} 進行通信", self.base_url);
        let otp = self.inner.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let (_, csr_cert) = CertUtils::generate_csr(
            self.private_key.clone(),
            "TW",
            "Taipei",
            "Taipei",
            "CHM Organization",
            "controller.chm.com",
            &["127.0.0.1", "localhost"],
        )?;
        let data = Otp {
            code: otp,
            csr_cert,
            days: 365,
        };
        let resp = client
            .post(format!("{}/init", self.base_url))
            .json(&data)
            .send()
            .await?
            .error_for_status()?;
        let signed_cert: SignedCertResponse = resp.json().await?;
        self.set_cert(signed_cert.cert);
        self.set_cert_chain(signed_cert.chain);
        Ok(())
    }
}

pub async fn first_run(marker_path: &Path) -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    let (pri_key, _) = CertUtils::generate_rsa_keypair(4096).expect("生成 RSA 金鑰對失敗");
    let mut conn = FirstStart::new("https://127.0.0.1:50052", pri_key.clone(), None);
    conn.inner = conn
        .inner
        .with_root_ca(Some(ProjectConst::certs_path().join("rootCA.pem")));
    conn.init().await?;
    if let Some(cert) = conn.cert {
        CertUtils::save_cert("controller", &conn.private_key, &cert).expect("儲存憑證失敗");
        tracing::info!("憑證已生成，請檢查 controller.pem 和 controller.key");
    } else {
        tracing::error!("未包含有效憑證，請檢查伺服器設定");
        return Err("未收到憑證".into());
    }

    std::fs::write(marker_path, "done")?;
    Ok(())
}
