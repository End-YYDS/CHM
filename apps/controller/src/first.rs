use std::path::{Path, PathBuf};

use crate::{ConResult, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{ClusterClient, Default_ClientCluster};
use chm_dns_resolver::uuid::Uuid;
use chm_grpc::tonic::async_trait;
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};

struct FirstStart {
    base_url:      String,
    private_key:   Vec<u8>,
    cert:          Option<Vec<u8>>,
    cert_chain:    Option<Vec<Vec<u8>>>,
    inner:         Default_ClientCluster,
    ca_unique_id:  Option<Uuid>,
    self_uuid:     Uuid,
    ca_hostname:   String,
    self_hostname: String,
}
struct FirstStartParams<T: Into<String>> {
    base_url:      T,
    private_key:   Vec<u8>,
    cert:          Option<Vec<u8>>,
    root_ca:       Option<PathBuf>,
    self_uuid:     Uuid,
    self_hostname: String,
}
impl FirstStart {
    pub fn new<T: Into<String>>(parms: FirstStartParams<T>) -> Self {
        let FirstStartParams { base_url, private_key, cert, root_ca, self_uuid, self_hostname } =
            parms;
        let base_url: String = base_url.into();
        Self {
            base_url: base_url.clone(),
            private_key,
            cert,
            cert_chain: None,
            inner: Default_ClientCluster::new(
                base_url,
                None::<String>,
                None::<PathBuf>,
                None::<PathBuf>,
                root_ca,
            ),
            ca_unique_id: None,
            self_uuid,
            ca_hostname: "".into(),
            self_hostname,
        }
    }
    pub fn set_cert(&mut self, cert: Vec<u8>) {
        self.cert = Some(cert);
    }
    pub fn set_cert_chain(&mut self, cert_chain: Vec<Vec<u8>>) {
        self.cert_chain = Some(cert_chain);
    }
    pub fn set_unique_id(&mut self, unique_id: Uuid) {
        self.ca_unique_id = Some(unique_id);
    }
    pub fn set_ca_hostname(&mut self, hostname: String) {
        self.ca_hostname = hostname
    }
}

#[derive(Debug, Deserialize)]
struct SignedCertResponse {
    cert:        Vec<u8>,
    chain:       Vec<Vec<u8>>,
    unique_id:   Uuid,
    ca_hostname: String,
}

#[derive(Debug, Clone, Serialize)]
struct Otp {
    code:     String,
    csr_cert: Vec<u8>,
    days:     u32,
    uuid:     Uuid,
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
        let common_name = format!("{}.chm.com", self.self_hostname);
        let (_, csr_cert) = CertUtils::generate_csr(
            self.private_key.clone(),
            "TW",
            "Taipei",
            "Taipei",
            "CHM Organization",
            common_name.as_str(),
            &["127.0.0.1", "localhost", common_name.as_str(), self.self_uuid.to_string().as_str()],
        )?;
        let data = Otp { code: otp, csr_cert, days: 365, uuid: self.self_uuid };
        let resp = client
            .post(format!("{}/init", self.base_url))
            .json(&data)
            .send()
            .await?
            .error_for_status()?;
        let signed_cert: SignedCertResponse = resp.json().await?;
        self.set_cert(signed_cert.cert);
        self.set_cert_chain(signed_cert.chain);
        self.set_unique_id(signed_cert.unique_id);
        self.set_ca_hostname(signed_cert.ca_hostname);
        Ok(())
    }
}

pub async fn first_run(marker_path: &Path) -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    let (pri_key, _) = CertUtils::generate_rsa_keypair(4096).expect("生成 RSA 金鑰對失敗");
    let (ca_url, self_uuid, self_hostname) = GlobalConfig::with(|cfg| {
        (cfg.server.ca_server.clone(), cfg.server.unique_id, cfg.server.hostname.clone())
    });
    let mut conn = FirstStart::new(FirstStartParams {
        base_url: ca_url.clone(),
        private_key: pri_key.clone(),
        cert: None,
        root_ca: Some(ProjectConst::certs_path().join("rootCA.pem")),
        self_uuid,
        self_hostname: self_hostname.clone(),
    });
    conn.init().await?;
    if let Some(ca_id) = conn.ca_unique_id {
        GlobalConfig::update_with(|cfg| {
            cfg.services_pool.services_uuid.insert(conn.ca_hostname.clone(), ca_id);
        });
    }
    if let Some(cert) = conn.cert {
        CertUtils::save_cert(&self_hostname, &conn.private_key, &cert).expect("儲存憑證失敗");
        tracing::info!("憑證已儲存至 {self_hostname}.pem 及 {self_hostname}.key");
    } else {
        tracing::error!("未包含有效憑證，請檢查伺服器設定");
        return Err("未收到憑證".into());
    }
    std::fs::write(marker_path, "done")?;
    GlobalConfig::save_config().await?;
    tracing::debug!("mCA UUID: {:?}", conn.ca_unique_id);
    Ok(())
}
