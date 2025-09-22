use crate::{cert::process::CertificateProcess, globals::GlobalConfig, PrivateKey, SignedCert, ID};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{api_resp, declare_init_route, Default_ServerCluster};
use openssl::x509::{X509Req, X509};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use uuid::Uuid;

#[derive(Serialize)]
struct SignedCertResponse {
    cert:        Vec<u8>,
    chain:       Vec<Vec<u8>>,
    unique_id:   Uuid,
    ca_hostname: String,
    port:        u16,
}

#[derive(Debug, Clone, Deserialize)]
struct InitRequest {
    csr_cert: Vec<u8>,
    days:     u32,
    uuid:     Uuid,
}

#[derive(Clone)]
struct AppState {
    cert_process: Arc<CertificateProcess>,
    unique_id:    Uuid,
    hostname:     String,
    port:         u16,
}
async fn init_data_handler(
    _req: &HttpRequest,
    data: Json<InitRequest>,
    state: Data<Arc<AppState>>,
) -> ControlFlow<HttpResponse, SignedCertResponse> {
    let csr_x509 =
        match X509Req::from_pem(&data.csr_cert).or_else(|_| X509Req::from_der(&data.csr_cert)) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!("解析 CSR 憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(BadRequest "無效的 CSR 憑證"));
            }
        };
    let signed_cert = match state.cert_process.sign_csr(&csr_x509, data.days).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("簽發 CSR 失敗: {:?}", e);
            return ControlFlow::Break(api_resp!(InternalServerError "簽發憑證失敗"));
        }
    };
    GlobalConfig::update_with(|cfg| {
        cfg.extend.controller.serial =
            CertUtils::cert_serial_sha256(&X509::from_pem(&signed_cert.0).unwrap())
                .expect("無法計算Serial");
        cfg.extend.controller.fingerprint =
            CertUtils::cert_fingerprint_sha256(&X509::from_pem(&signed_cert.0).unwrap())
                .expect("無法計算fingerprint");
        cfg.extend.controller.uuid = data.uuid;
    });
    if let Err(e) = GlobalConfig::save_config().await {
        tracing::error!("儲存設定失敗: {:?}", e);
        return ControlFlow::Break(api_resp!(InternalServerError "儲存設定失敗"));
    }
    ControlFlow::Continue(SignedCertResponse {
        cert:        signed_cert.0,
        chain:       signed_cert.1,
        unique_id:   state.unique_id,
        ca_hostname: state.hostname.clone(),
        port:        state.port,
    })
}
declare_init_route!(init_data_handler, data = InitRequest, extras = (state: Arc<AppState>), ret = SignedCertResponse);
pub struct MiniController {
    sign_cert:    Option<SignedCert>,
    private_key:  Option<PrivateKey>,
    cert_process: Arc<CertificateProcess>,
}
impl MiniController {
    pub fn new(
        private_key: Option<PrivateKey>,
        sign_cert: Option<SignedCert>,
        cert_process: Arc<CertificateProcess>,
    ) -> Self {
        Self { sign_cert, private_key, cert_process }
    }
    pub async fn start(
        &self,
        addr: SocketAddr,
        id: Uuid,
    ) -> ControlFlow<Box<dyn std::error::Error + Send + Sync>, ()> {
        let (otp_len, root_ca, hostname, self_port) = GlobalConfig::with(|cfg| {
            (
                cfg.server.otp_len,
                cfg.certificate.root_ca.clone(),
                cfg.server.hostname.clone(),
                cfg.server.port,
            )
        });
        let x509_cert = self.sign_cert.clone().expect("MiniController 憑證獲取失敗");
        let key = self.private_key.clone().expect("MiniController 私鑰獲取失敗");
        tracing::info!("在 {addr} 啟動MiniController，等待 Controller 的初始化請求...");
        let init_server = Default_ServerCluster::new(
            addr.to_string(),
            x509_cert,
            key,
            Some(root_ca),
            otp_len,
            ID,
        )
        .with_otp_rotate_every(Duration::from_secs(30))
        .add_configurer(init_route())
        .with_app_data(AppState {
            cert_process: self.cert_process.clone(),
            unique_id:    id,
            hostname:     hostname.clone(),
            port:         self_port,
        });
        match init_server.init().await {
            ControlFlow::Continue(()) => {
                tracing::info!("初始化完成，啟動正式服務...");
                ControlFlow::Continue(())
            }
            ControlFlow::Break(_) => {
                tracing::warn!("初始化未完成 (Ctrl+C)，程式結束");
                ControlFlow::Break("初始化未完成".into())
            }
        }
    }
}
