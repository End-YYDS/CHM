use std::path::{Path, PathBuf};

use crate::{ConResult, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{init_with, Default_ClientCluster};
use chm_project_const::uuid::Uuid;
use serde::{Deserialize, Serialize};

struct FirstStart {
    root_ca:       Option<Vec<u8>>,
    private_key:   Option<Vec<u8>>,
    cert:          Option<Vec<u8>>,
    cert_chain:    Option<Vec<Vec<u8>>>,
    inner:         Default_ClientCluster,
    ca_unique_id:  Option<Uuid>,
    self_uuid:     Uuid,
    ca_hostname:   String,
    self_hostname: String,
    ca_port:       u16,
}
struct FirstStartParams {
    base_url:      String,
    private_key:   Option<Vec<u8>>,
    cert:          Option<Vec<u8>>,
    self_uuid:     Uuid,
    self_hostname: String,
}
#[derive(Debug, Deserialize)]
struct SignedCertResponse {
    root_ca:     Vec<u8>,
    cert:        Vec<u8>,
    chain:       Vec<Vec<u8>>,
    unique_id:   Uuid,
    ca_hostname: String,
    port:        u16,
}

#[derive(Debug, Clone, Serialize)]
struct InitData {
    csr_cert: Vec<u8>,
    days:     u32,
    uuid:     Uuid,
}
impl FirstStart {
    pub fn new(parms: FirstStartParams) -> Self {
        let FirstStartParams { base_url, private_key, cert, self_uuid, self_hostname } = parms;
        Self {
            private_key,
            cert,
            cert_chain: None,
            inner: Default_ClientCluster::new(
                base_url,
                None::<String>,
                None::<PathBuf>,
                None::<PathBuf>,
                None::<PathBuf>,
                None::<String>,
            ),
            ca_unique_id: None,
            self_uuid,
            ca_hostname: "".into(),
            self_hostname,
            ca_port: 50052,
            root_ca: None,
        }
    }
    pub async fn init(&mut self) -> ConResult<()> {
        let common_name = format!("{}.chm.com", self.self_hostname);
        let uuid_s = self.self_uuid.to_string();
        let sans: Vec<&str> = vec!["127.0.0.1", "localhost", common_name.as_str(), uuid_s.as_str()];
        // TODO: 從Config讀取
        let (pri_key, csr_cert) = CertUtils::generate_csr_with_new_key(
            4096,
            "TW",
            "Taipei",
            "Taipei",
            "CHM Organization",
            common_name.as_str(),
            &sans,
        )?;
        let payload = InitData { csr_cert, days: 365, uuid: self.self_uuid };
        let resp: SignedCertResponse = init_with!(self.inner, payload, as SignedCertResponse)?;
        self.root_ca = Some(resp.root_ca);
        self.private_key = Some(pri_key);
        self.cert = Some(resp.cert);
        self.cert_chain = Some(resp.chain);
        self.ca_unique_id = Some(resp.unique_id);
        self.ca_hostname = resp.ca_hostname;
        self.ca_port = resp.port;
        Ok(())
    }
}

pub async fn first_run(marker_path: &Path) -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    let (ca_url, self_uuid, self_hostname, root_ca) = GlobalConfig::with(|cfg| {
        (
            cfg.extend.server_ext.ca_server.clone(),
            cfg.server.unique_id,
            cfg.server.hostname.clone(),
            cfg.certificate.root_ca.clone(),
        )
    });
    let mut conn = FirstStart::new(FirstStartParams {
        base_url: ca_url,
        private_key: None,
        cert: None,
        self_uuid,
        self_hostname: self_hostname.clone(),
    });
    conn.init().await?;
    if let Some(ca_id) = conn.ca_unique_id {
        GlobalConfig::update_with(|cfg| {
            #[cfg(debug_assertions)]
            cfg.extend
                .services_pool
                .services_uuid
                .insert(conn.ca_hostname.clone(), format!("{ca_id}:{}", conn.ca_port));
            #[cfg(not(debug_assertions))]
            cfg.extend.services_pool.services_uuid.insert(conn.ca_hostname.clone(), ca_id);
        });
    }
    if let Some(ca_cert) = conn.root_ca {
        tokio::fs::write(&root_ca, &ca_cert).await?;
        tracing::info!("從 mCA 取得的 RootCA 憑證已儲存至 {}", root_ca.display());
    }
    if let Some(cert) = conn.cert {
        let private_key = conn.private_key.expect("缺少私鑰");
        CertUtils::save_cert(&self_hostname, &private_key, &cert).expect("儲存憑證失敗");
        tracing::info!("憑證已儲存至 {self_hostname}.pem 及 {self_hostname}.key");
    } else {
        tracing::error!("未包含有效憑證，請檢查伺服器設定");
        return Err("未收到憑證".into());
    }
    std::fs::write(marker_path, "done")?;
    GlobalConfig::save_config().await?;
    GlobalConfig::reload_config().await?;
    tracing::debug!("mCA UUID: {:?}", conn.ca_unique_id);
    Ok(())
}
