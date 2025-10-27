use std::path::PathBuf;

use crate::{ConResult, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{atomic_write, init_with, Default_ClientCluster, ServiceDescriptor};
use chm_project_const::{uuid::Uuid, ProjectConst};
use serde::{Deserialize, Serialize};
struct FirstStart {
    inner:     Default_ClientCluster,
    self_uuid: Uuid,
}
struct FirstStartParams {
    base_url:  String,
    self_uuid: Uuid,
    mdns_url:  String,
}
#[derive(Debug, Deserialize)]
struct SignedCertResponse {
    root_ca:      Vec<u8>,
    cert:         Vec<u8>,
    chain:        Vec<Vec<u8>>,
    ca_hostname:  String,
    port:         u16,
    service_desp: ServiceDescriptor,
}

#[derive(Debug, Clone, Serialize)]
struct InitData {
    csr_cert: Vec<u8>,
    days:     u32,
    uuid:     Uuid,
}
#[allow(unused)]
#[derive(Debug)]
struct InitOutput {
    root_ca:      Vec<u8>,
    private_key:  Vec<u8>,
    cert:         Vec<u8>,
    cert_chain:   Vec<Vec<u8>>,
    ca_hostname:  String,
    ca_port:      u16,
    service_desp: ServiceDescriptor,
}
impl FirstStart {
    pub fn new(parms: FirstStartParams) -> Self {
        let FirstStartParams { base_url, self_uuid, mdns_url } = parms;
        Self {
            inner: Default_ClientCluster::new(
                base_url,
                Some(mdns_url),
                None::<PathBuf>,
                None::<PathBuf>,
                None::<PathBuf>,
                None::<String>,
            ),
            self_uuid,
        }
    }
    pub async fn init(&mut self) -> ConResult<InitOutput> {
        let uuid_s = self.self_uuid.to_string();
        let certinfo = GlobalConfig::with(|cfg| cfg.certificate.cert_info.clone());
        let mut san_extend = certinfo.san.clone();
        san_extend.push(uuid_s);
        let (pri_key, csr_cert) = CertUtils::generate_csr_with_new_key(
            certinfo.bits,
            &certinfo.country,
            &certinfo.state,
            &certinfo.locality,
            ProjectConst::PROJECT_NAME,
            format!("{}.chm.com", &certinfo.cn).as_str(),
            san_extend,
        )?;
        let payload = InitData { csr_cert, days: 365, uuid: self.self_uuid };
        let resp: SignedCertResponse = init_with!(self.inner, payload, as SignedCertResponse)?;
        Ok(InitOutput {
            root_ca:      resp.root_ca,
            private_key:  pri_key,
            cert:         resp.cert,
            cert_chain:   resp.chain,
            ca_hostname:  resp.ca_hostname,
            ca_port:      resp.port,
            service_desp: resp.service_desp,
        })
    }
}

pub async fn first_run(ca_url: String, otp_code: Option<String>) -> ConResult<()> {
    tracing::info!("第一次啟動，正在初始化...");
    let (self_uuid, self_hostname, root_ca, mdns_url) = GlobalConfig::with(|cfg| {
        (
            cfg.server.unique_id,
            cfg.server.hostname.clone(),
            cfg.certificate.root_ca.clone(),
            cfg.server.dns_server.clone(),
        )
    });
    let mut conn = FirstStart::new(FirstStartParams { base_url: ca_url, self_uuid, mdns_url });
    conn.inner = conn.inner.with_otp_code(otp_code);
    let output = conn.init().await?;
    GlobalConfig::update_with(|cfg| {
        let service_desp = output.service_desp.clone();
        cfg.extend
            .services_pool
            .services
            .entry(service_desp.kind)
            .or_default()
            .insert(service_desp);
    });
    atomic_write(&root_ca, &output.root_ca).await?;
    CertUtils::save_cert(&self_hostname, &output.private_key, &output.cert)
        .map_err(|e| format!("儲存憑證失敗：{e}"))?;
    tracing::info!("已儲存憑證與私鑰：{name}.pem / {name}.key", name = self_hostname);

    GlobalConfig::save_config().await?;
    GlobalConfig::reload_config().await?;
    tracing::debug!("mCA UUID: {:?}", output.service_desp.uuid);
    Ok(())
}
