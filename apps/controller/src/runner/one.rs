use std::path::{Path, PathBuf};

use crate::{reload_globals, ConResult, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{ClusterClient, Default_ClientCluster};
use chm_dns_resolver::uuid::Uuid;
use chm_grpc::tonic::async_trait;
use chm_project_const::ProjectConst;
use serde::{Deserialize, Serialize};

struct FirstStart {
    base_url:     String,
    private_key:  Vec<u8>,
    cert:         Option<Vec<u8>>,
    cert_chain:   Option<Vec<Vec<u8>>>,
    inner:        Default_ClientCluster,
    ca_unique_id: Option<Uuid>,
    self_uuid:    Uuid,
}
impl FirstStart {
    pub fn new(
        base_url: impl Into<String>,
        private_key: Vec<u8>,
        cert: Option<Vec<u8>>,
        self_uuid: Uuid,
    ) -> Self {
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
                None::<PathBuf>,
            ),
            ca_unique_id: None,
            self_uuid,
        }
    }
    pub fn set_cert(&mut self, cert: Vec<u8>) {
        self.cert = Some(cert);
    }
    pub fn set_cert_chain(&mut self, cert_chain: Vec<Vec<u8>>) {
        self.cert_chain = Some(cert_chain);
    }
    pub fn set_unique_id(&mut self, unique_id: Uuid) {
        // let unique_id = Uuid::parse_str(&unique_id).unwrap_or_else(|_| {
        //     tracing::error!("無效的 unique_id，使用預設值");
        //     Uuid::new_v4()
        // });
        self.ca_unique_id = Some(unique_id);
    }
}

#[derive(Debug, Deserialize)]
struct SignedCertResponse {
    cert:      Vec<u8>,
    chain:     Vec<Vec<u8>>,
    unique_id: Uuid,
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
        let (_, csr_cert) = CertUtils::generate_csr(
            self.private_key.clone(),
            "TW",
            "Taipei",
            "Taipei",
            "CHM Organization",
            "controller.chm.com",
            &["127.0.0.1", "localhost", "controller.chm.com"],
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
        self.set_unique_id(signed_cert.unique_id); // TODO: 這個unique_id應該從mCA獲取，之後寫入全域設定
        Ok(())
    }
}

pub async fn first_run(marker_path: &Path) -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    // let mca_path = {
    //     print!("請輸入mCA位置: ");
    //     std::io::stdout().flush()?;
    //     let mut input = String::new();
    //     std::io::stdin().read_line(&mut input)?;
    //     Some(input.trim()).filter(|s|
    // !s.is_empty()).unwrap_or(DEFAULT_CA).to_string() };
    // let mdns_path = {
    //     print!("請輸入mDNS位置: ");
    //     std::io::stdout().flush()?;
    //     let mut input = String::new();
    //     std::io::stdin().read_line(&mut input)?;
    //     Some(input.trim()).filter(|s|
    // !s.is_empty()).unwrap_or(DEFAULT_DNS).to_string() };
    let (pri_key, _) = CertUtils::generate_rsa_keypair(4096).expect("生成 RSA 金鑰對失敗");
    let r = GlobalConfig::read().await;
    let ca_url = r.settings.server.ca_server.clone();
    let self_uuid = r.settings.server.unique_id;
    drop(r);
    let mut conn = FirstStart::new(ca_url, pri_key.clone(), None, self_uuid);
    conn.inner = conn.inner.with_root_ca(Some(ProjectConst::certs_path().join("rootCA.pem")));
    conn.init().await?;
    if let Some(cert) = conn.cert {
        CertUtils::save_cert("controller", &conn.private_key, &cert).expect("儲存憑證失敗");
        tracing::info!("憑證已生成，請檢查 controller.pem 和 controller.key");
    } else {
        tracing::error!("未包含有效憑證，請檢查伺服器設定");
        return Err("未收到憑證".into());
    }
    std::fs::write(marker_path, "done")?;
    reload_globals().await;
    GlobalConfig::save_config().await?;
    tracing::debug!("mCA UUID: {:?}", conn.ca_unique_id);
    // TODO: 將連線資訊寫入檔案, 並且將mCA的UUID寫入全域設定
    Ok(())
}
