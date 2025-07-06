use std::{fmt::Debug, path::PathBuf, sync::Arc};

use actix_tls::accept::openssl::TlsStream;
use actix_web::{
    post,
    web::{self},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chm_cert_utils::CertUtils;
use openssl::{
    error::ErrorStack,
    ssl::{SslAcceptorBuilder, SslFiletype, SslMethod, SslVerifyMode},
    x509::X509,
};
use serde::Deserialize;
use tokio::net::TcpStream;

use crate::ApiResponse;

type ServerCert = PathBuf;
type ServerKey = PathBuf;
pub type ValidCertHandler = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;
#[derive(Debug, Clone)]
pub struct PeerCerts(Vec<X509>);
#[derive(Debug, Clone, Deserialize)]
struct Otp {
    code: String,
}
pub struct ServerCluster {
    bind_address:       String,
    cert_chain:         Option<(ServerCert, ServerKey)>,
    root_ca:            Option<PathBuf>,
    otp:                Option<String>,
    otp_len:            usize,
    ssl_acceptor:       Option<openssl::ssl::SslAcceptorBuilder>,
    custom_otp:         bool,
    marker_path:        Option<PathBuf>,
    valid_cert_handler: Option<ValidCertHandler>,
}
impl Debug for ServerCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCluster")
            .field("bind_address", &self.bind_address)
            .field("cert_chain", &self.cert_chain)
            .field("root_ca", &self.root_ca)
            .field("otp", &self.otp)
            .field("otp_len", &self.otp_len)
            .field("custom_otp", &self.custom_otp)
            .field("marker_path", &self.marker_path)
            .finish()
    }
}

impl Default for ServerCluster {
    fn default() -> Self {
        Self {
            bind_address:       "0.0.0.0:50051".into(),
            cert_chain:         None,
            root_ca:            None,
            otp:                None,
            otp_len:            6,
            ssl_acceptor:       None,
            custom_otp:         false,
            marker_path:        None,
            valid_cert_handler: None,
        }
    }
}

impl ServerCluster {
    pub fn new(
        addr: impl Into<String>,
        cert_path: impl Into<PathBuf>,
        cert_key: impl Into<PathBuf>,
        root_ca: impl Into<PathBuf>,
        otp_len: usize,
        marker_path: impl Into<PathBuf>,
    ) -> Self {
        Self::default()
            .with_bind_addr(addr)
            .with_cert_chain(cert_path, cert_key)
            .with_root_ca(root_ca)
            .with_otp_len(otp_len)
            .with_otp()
            .with_marker_path(marker_path)
            .build_ssl_acceptor()
            .expect("Failed to build SSL acceptor")
    }
    pub fn with_valid_cert_handler<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.valid_cert_handler = Some(Arc::new(f));
        self
    }
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = addr.into();
        self
    }
    pub fn with_cert_chain(
        mut self,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        self.cert_chain = Some((cert_path.into(), key_path.into()));
        self
    }
    pub fn with_root_ca(mut self, ca_path: impl Into<PathBuf>) -> Self {
        self.root_ca = Some(ca_path.into());
        self
    }
    pub fn with_otp_len(mut self, len: usize) -> Self {
        self.otp_len = len;
        self
    }
    pub fn with_otp(mut self) -> Self {
        self.otp = Some(chm_password::generate_otp(self.otp_len));
        self
    }
    pub fn with_marker_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.marker_path = Some(path.into());
        self
    }
    pub fn with_ssl_acceptor(mut self, acceptor: openssl::ssl::SslAcceptorBuilder) -> Self {
        self.ssl_acceptor = Some(acceptor);
        self
    }
    pub fn with_custom_otp(mut self, custom: bool, passwd: Option<impl Into<String>>) -> Self {
        self.custom_otp = custom;
        if custom {
            if let Some(passwd) = passwd {
                self.otp = Some(passwd.into());
            } else {
                self.otp = Some(chm_password::generate_otp(self.otp_len));
            }
        }
        self
    }
    pub fn make_ssl_acceptor_builder(&self) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        if let Some((ref cert_path, ref key_path)) = self.cert_chain {
            builder.set_private_key_file(key_path, SslFiletype::PEM)?;
            builder.set_certificate_chain_file(cert_path)?;
        }
        if let Some(ref ca_path) = self.root_ca {
            builder.set_ca_file(ca_path)?;
        }
        builder.check_private_key()?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        Ok(builder)
    }
    fn build_ssl_acceptor(mut self) -> Result<Self, openssl::error::ErrorStack> {
        let builder = self.make_ssl_acceptor_builder()?;
        self.ssl_acceptor = Some(builder);
        Ok(self)
    }
}
#[async_trait::async_trait]
impl super::ClusterServer for ServerCluster {
    async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting server on {}", self.bind_address);
        tracing::info!("Using OTP: {:?}", self.otp);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let bind_addr = self.bind_address.clone();
        let otp_code = self.otp.clone().expect("otp should have been set by new()");
        let marker_path = self.marker_path.clone().expect("marker_path should have been set");
        let ssl_builder = self.make_ssl_acceptor_builder()?;
        let valid_cb = self.valid_cert_handler.clone().expect("請先呼叫 with_valid_cert_handler");
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(marker_path.clone()))
                .app_data(web::Data::new(otp_code.clone()))
                .app_data(web::Data::new(valid_cb.clone()))
                .app_data(tx_clone.clone())
                .service(init_api)
        })
        .on_connect(|conn, ext| {
            if let Some(stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
                let ssl_ref = stream.ssl();
                if let Some(cert) = ssl_ref.peer_certificate() {
                    ext.insert(PeerCerts(vec![cert]));
                }
            }
        })
        .bind_openssl(bind_addr, ssl_builder)?
        .disable_signals()
        .run();
        let handle = server.handle();
        let h = handle.clone();
        tokio::spawn(async move {
            if rx.recv().await.is_some() {
                h.stop(false).await;
            }
        });
        let h2 = handle.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("CtrlC Error");
            h2.stop(false).await;
        });
        server.await?;
        Ok(())
    }
}

#[post("init")]
/// 初始化 API，寫入 marker 檔案並關閉伺服器
/// # 參數
/// * `req`: HTTP 請求
/// * `shutdown_tx`: 用於關閉伺服器的通道
/// * `marker_path`: 用於標記初始化完成的檔案路徑
/// * `otp_code`: 用於驗證的 OTP 代碼
/// * `valid_cb`: 用於驗證憑證的回調函數
/// * `data`: 包含 OTP 代碼的 JSON 請求體
/// # 回傳
/// * `HttpResponse`: 返回 HTTP 響應，成功時為 Ok，失敗時為 InternalServerError
async fn init_api(
    req: HttpRequest,
    shutdown_tx: web::Data<tokio::sync::mpsc::Sender<()>>,
    marker_path: web::Data<PathBuf>,
    otp_code: web::Data<String>,
    valid_cb: web::Data<ValidCertHandler>,
    data: web::Json<Otp>,
) -> impl Responder {
    if data.code.as_str() != otp_code.as_str() {
        tracing::error!("OTP 驗證失敗: {}", data.code);
        return HttpResponse::Unauthorized()
            .json(ApiResponse { message: "OTP 驗證失敗".to_string(), ok: false });
    }
    if let Some(peer) = req.conn_data::<PeerCerts>() {
        let serial = peer.0.first().and_then(|cert| CertUtils::cert_serial_sha256(cert).ok());
        let fingerprint =
            peer.0.first().and_then(|cert| CertUtils::cert_fingerprint_sha256(cert).ok());
        if let (Some(s), Some(f)) = (serial, fingerprint) {
            {
                if !(valid_cb.as_ref())(&s, &f) {
                    return HttpResponse::Forbidden()
                        .json(ApiResponse {
                            message: "憑證驗證失敗".to_string(), ok: false
                        });
                }
            }
        }
    } else {
        tracing::warn!("沒有找到 PeerCerts，請確保使用正確的憑證連接");
        return HttpResponse::PreconditionFailed().json(ApiResponse {
            message: "沒有找到 PeerCerts，請確保使用正確的憑證連接".to_string(),
            ok:      false,
        });
    }

    if let Err(e) = tokio::fs::write(marker_path.get_ref(), b"done").await {
        eprint!("寫入marker檔案失敗: {e}");
        return HttpResponse::InternalServerError()
            .json(ApiResponse { message: format!("寫入marker檔案失敗: {e}"), ok: false });
    }
    if cfg!(debug_assertions) {
        tracing::info!("初始化完成，關閉伺服器");
    }
    let _ = shutdown_tx.send(()).await;
    HttpResponse::Ok()
        .json(ApiResponse {
            message: "初始化完成，web服務器將關閉".to_string(), ok: true
        })
}
