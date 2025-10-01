use crate::{cert::process::CertificateProcess, globals::GlobalConfig, PrivateKey, SignedCert, ID};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, declare_init_route, Default_ServerCluster, ServiceDescriptor, ServiceKind,
};
use openssl::x509::{X509Req, X509};
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use uuid::Uuid;

#[derive(Serialize)]
struct SignedCertResponse {
    root_ca:      Vec<u8>,
    cert:         Vec<u8>,
    chain:        Vec<Vec<u8>>,
    ca_hostname:  String,
    port:         u16,
    service_desp: ServiceDescriptor,
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
    socket:       SocketAddrV4,
    root_ca:      Vec<u8>,
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
    let service_desp = ServiceDescriptor {
        kind:        ServiceKind::Mca,
        uri:         format!("https://{}:{}", state.socket.ip(), state.socket.port()),
        health_name: Some("ca.CA".to_string()),
        hostname:    ID.to_string(),
        is_server:   true,
        uuid:        state.unique_id,
    };
    ControlFlow::Continue(SignedCertResponse {
        root_ca: state.root_ca.clone(),
        cert: signed_cert.0,
        chain: signed_cert.1,
        ca_hostname: state.hostname.clone(),
        port: state.socket.port(),
        service_desp,
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
        addr: SocketAddrV4,
        id: Uuid,
    ) -> ControlFlow<Box<dyn std::error::Error + Send + Sync>, ()> {
        let (otp_len, otp_time, root_ca, hostname) = GlobalConfig::with(|cfg| {
            (
                cfg.server.otp_len,
                cfg.server.otp_time,
                cfg.certificate.root_ca.clone(),
                cfg.server.hostname.clone(),
            )
        });
        let x509_cert = self.sign_cert.clone().expect("MiniController 憑證獲取失敗");
        let key = self.private_key.clone().expect("MiniController 私鑰獲取失敗");
        tracing::info!("在 {addr} 啟動MiniController，等待 Controller 的初始化請求...");
        let root_ca_bytes = match tokio::fs::read(&root_ca).await {
            Ok(ca) => ca,
            Err(e) => {
                tracing::error!("讀取 RootCA 憑證失敗: {:?}", e);
                return ControlFlow::Break("讀取 RootCA 憑證失敗".into());
            }
        };
        let init_server = Default_ServerCluster::new(
            addr.to_string(),
            x509_cert,
            key,
            Some(root_ca),
            otp_len,
            ID,
        )
        .with_otp_rotate_every(otp_time)
        .add_configurer(init_route())
        .with_app_data(AppState {
            root_ca:      root_ca_bytes,
            cert_process: self.cert_process.clone(),
            unique_id:    id,
            hostname:     hostname.clone(),
            socket:       addr,
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
