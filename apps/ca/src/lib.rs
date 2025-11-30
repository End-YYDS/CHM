pub mod cert;
// pub mod config;
pub mod connection;
pub mod mini_controller;
use crate::{
    cert::{crl::CrlList, process::CertificateProcess},
    connection::MyCa,
    mini_controller::MiniController,
};
pub use crate::{config::config, globals::GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_config_bus::{declare_config, declare_config_bus};
use chm_dns_resolver::get_local_hostname;
use chm_grpc::{
    ca::ca_server::CaServer,
    crl::crl_server,
    tonic::{self, codec::CompressionEncoding},
    tonic_health,
};
use chm_project_const::ProjectConst;
use futures::{future::BoxFuture, FutureExt};
use openssl::x509::{X509Req, X509};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddrV4,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};
use tokio::sync::watch;
use tonic::{
    transport::{Identity, ServerTlsConfig},
    Request, Status,
};
use tonic_async_interceptor::async_interceptor;
use tonic_health::server::health_reporter;
use tower::ServiceBuilder;
// use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use uuid::Uuid;

/// 定義一個簡化的結果類型，用於返回結果或錯誤
pub type CaResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
/// 定義已經簽署的憑證類型
pub type SignedCert = Vec<u8>;
/// 定義憑證鏈類型，包含已簽署的憑證和 CA 憑證
pub type ChainCerts = Vec<SignedCert>;
/// 定義私鑰類型
pub type PrivateKey = Vec<u8>;
/// 定義 CSR 憑證類型
pub type CsrCert = Vec<u8>;
type CheckFuture = BoxFuture<'static, Result<Request<()>, Status>>;
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMmCA";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50052;
pub const DEFAULT_OTP_LEN: usize = 6;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;
pub const DEFAULT_TIMEOUT: u64 = 10;
pub const DEFAULT_BITS: i32 = 256;
pub const DEFAULT_CRL_UPDATE_INTERVAL: u64 = 3600; // 1 小時

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CaExtension {
    #[serde(default)]
    pub cert_ext:   CertificateExt,
    #[serde(default)]
    pub controller: Controller,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExt {
    #[serde(default = "CertificateExt::default_rootca_key")]
    /// 根憑證的私鑰路徑
    pub rootca_key:          PathBuf,
    #[serde(default = "CertificateExt::default_bits")]
    pub rand_bits:           i32,
    #[serde(with = "humantime_serde", default = "CertificateExt::default_crl_update_interval")]
    pub crl_update_interval: std::time::Duration,
    #[serde(flatten)]
    #[serde(default)]
    pub backend:             BackendConfig,
}
impl Default for CertificateExt {
    fn default() -> Self {
        CertificateExt {
            rootca_key:          CertificateExt::default_rootca_key(),
            backend:             BackendConfig::default(),
            rand_bits:           CertificateExt::default_bits(),
            crl_update_interval: CertificateExt::default_crl_update_interval(),
        }
    }
}
impl CertificateExt {
    fn default_bits() -> i32 {
        DEFAULT_BITS
    }
    fn default_crl_update_interval() -> std::time::Duration {
        std::time::Duration::from_secs(DEFAULT_CRL_UPDATE_INTERVAL)
    }
    fn default_rootca_key() -> PathBuf {
        ProjectConst::certs_path().join("rootCA.key")
    }
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum BackendConfig {
    /// SQLite 資料庫後端專屬設定
    /// 預設使用 `certs/cert_store.db` 作為資料庫檔案
    /// 最大連線數量預設為 5，逾時時間預設為 10 秒
    Sqlite {
        #[serde(default = "SqliteSettings::default_store_path")]
        store_path:      String,
        #[serde(default = "SqliteSettings::default_max_connections")]
        max_connections: u32,
        #[serde(default = "SqliteSettings::default_timeout")]
        timeout:         u64,
    },
}
impl Default for BackendConfig {
    fn default() -> Self {
        BackendConfig::Sqlite {
            store_path:      SqliteSettings::default_store_path(),
            max_connections: SqliteSettings::default_max_connections(),
            timeout:         SqliteSettings::default_timeout(),
        }
    }
}

struct SqliteSettings;
impl SqliteSettings {
    fn default_store_path() -> String {
        ProjectConst::db_path().join("cert_store.db").display().to_string()
    }
    fn default_max_connections() -> u32 {
        DEFAULT_MAX_CONNECTIONS
    }
    fn default_timeout() -> u64 {
        DEFAULT_TIMEOUT
    }
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
/// 控制器設定
pub struct Controller {
    /// 控制器的指紋，用於識別和驗證
    #[serde(default = "Controller::default_fingerprint")]
    pub fingerprint: String,
    /// 控制器的序列號，用於唯一標識
    #[serde(default = "Controller::default_serial")]
    pub serial:      String,
    /// 控制器的UUID
    #[serde(default = "Controller::default_uuid")]
    pub uuid:        Uuid,
}

impl Controller {
    /// 取得控制器的預設指紋
    pub fn default_fingerprint() -> String {
        "".into()
    }
    /// 取得控制器的預設序列號
    pub fn default_serial() -> String {
        "".into()
    }
    pub fn default_uuid() -> Uuid {
        Uuid::nil()
    }
}

declare_config!(extend = crate::CaExtension);
declare_config_bus!();

fn get_ssl_info(req: &Request<()>) -> CaResult<(X509, String)> {
    let peer_der_vec =
        req.peer_certs().ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
    let peer_slice: &[tonic::transport::CertificateDer] = peer_der_vec.as_ref().as_slice();
    let leaf = peer_slice
        .first()
        .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;
    let x509 = X509::from_der(leaf)
        .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))
        .inspect_err(|e| tracing::error!(?e))?;
    let serial = CertUtils::cert_serial_sha256(&x509)
        .map_err(|e| Status::internal(format!("Serial sha256 failed: {e}")))
        .inspect_err(|e| tracing::error!(?e))?;
    Ok((x509, serial))
}

/// 建立一個 gRPC 的 CRL 檢查攔截器
/// # 參數
/// * `cert_handler`: 憑證處理器，用於檢查 CRL
/// # 回傳
/// * `impl Fn(Request<()>) -> Result<Request<()>, Status>`: 返回一個攔截器函數
fn make_ca_middleware(
    cert_handler: Arc<CertificateProcess>,
    controller_args: (String, String),
) -> impl Fn(Request<()>) -> CheckFuture + Clone + Send + Sync + 'static {
    move |req: Request<()>| {
        let cert_handler = cert_handler.clone();
        let controller_args = controller_args.clone();
        async move {
            let req = check_revoke(cert_handler.clone(), req).await?;
            check_controller(cert_handler, controller_args, req).await
        }
        .boxed()
    }
}
async fn check_controller(
    cert_handler: Arc<CertificateProcess>,
    controller_args: (String, String),
    req: Request<()>,
) -> Result<Request<()>, Status> {
    let (x509, _) = get_ssl_info(&req)
        .map_err(|e| Status::internal(format!("SSL info failed: {e}")))
        .inspect_err(|e| tracing::error!(?e))?;
    let is_ctrl = cert_handler
        .is_controller_cert(&x509, controller_args.clone())
        .map_err(|e| Status::internal(format!("Controller check failed: {e}")))
        .inspect_err(|e| tracing::error!(?e))?;
    if !is_ctrl {
        return Err(Status::permission_denied("Only controller cert is allowed"));
    }

    Ok(req)
}
async fn check_revoke(
    cert_handler: Arc<CertificateProcess>,
    req: Request<()>,
) -> Result<Request<()>, Status> {
    let (_, serial) = get_ssl_info(&req)
        .map_err(|e| Status::internal(format!("SSL info failed: {e}")))
        .inspect_err(|e| tracing::error!(?e))?;
    if cert_handler.get_crl().is_revoked(&serial).await {
        return Err(Status::unauthenticated("Certificate was revoked"));
    }
    Ok(req)
}

fn make_crl_middleware(
    cert_handler: Arc<CertificateProcess>,
) -> impl Fn(Request<()>) -> CheckFuture + Clone + Send + Sync + 'static {
    move |req: Request<()>| {
        let cert_handler = cert_handler.clone();
        async move { check_revoke(cert_handler, req).await }.boxed()
    }
}

/// 啟動 gRPC 服務
/// # 參數
/// * `addr`: gRPC 服務的地址
/// * `cert_handler`: 憑證處理器，用於憑證簽署和 CRL 驗證
/// # 回傳
/// * `Result<(), Box<dyn std::error::Error>>`: 返回結果，成功時為 Ok，失敗時為
///   Err
pub async fn start_grpc(addr: SocketAddrV4, cert_handler: Arc<CertificateProcess>) -> CaResult<()> {
    let (cert_update_tx, mut cert_update_rx) = watch::channel(());
    loop {
        let mut rx = cert_update_rx.clone();
        // 設定 TLS
        let (key, cert) = GlobalConfig::with(|cfg| {
            (cfg.certificate.client_key.clone(), cfg.certificate.client_cert.clone())
        });

        let (key, cert) = CertUtils::cert_from_path(&cert, &key, None)?;
        let identity = Identity::from_pem(cert, key);
        let mut tls = ServerTlsConfig::new().identity(identity).client_ca_root(
            tonic::transport::Certificate::from_pem(cert_handler.get_ca_cert().to_pem()?),
        );
        if cfg!(debug_assertions) {
            tls = tls.use_key_log();
        }
        // 啟動健康檢查服務
        let (health_reporter, health_service) = health_reporter();
        health_reporter.set_serving::<CaServer<MyCa>>().await;
        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("[gRPC] 收到 Ctrl-C，開始關閉...");
                    }
                    Ok(_) = rx.changed() => {
                        tracing::info!("[gRPC] 憑證更新，開始重新啟動 gRPC...");
                    }
                }
                health_reporter.set_not_serving::<CaServer<MyCa>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        let ca_layer =
            async_interceptor(make_ca_middleware(cert_handler.clone(), controller_args.clone()));
        let ca_svc = ServiceBuilder::new().layer(ca_layer).service(
            CaServer::new(MyCa {
                cert:     cert_handler.clone(),
                reloader: cert_update_tx.clone(),
            })
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd),
        );
        let crl_layer = async_interceptor(make_crl_middleware(cert_handler.clone()));
        let crl_svc = ServiceBuilder::new().layer(crl_layer).service(
            crl_server::CrlServer::new(CrlList { cert: cert_handler.clone() })
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd),
        );
        tracing::info!("[gRPC] 啟動 gRPC 服務於 {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .add_service(ca_svc)
            .add_service(crl_svc)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);
        // let server = tonic::transport::Server::builder()
        //     .layer(
        //         TraceLayer::new_for_grpc()
        //             .make_span_with(DefaultMakeSpan::new())
        //             .on_response(DefaultOnResponse::new()),
        //     )
        //
        if let Err(e) = server.await {
            tracing::error!("[gRPC] 啟動失敗: {e:?}");
        }
        if cert_update_rx.has_changed().unwrap_or(false) {
            tracing::info!("[gRPC] 憑證更新，重新啟動 gRPC 服務");
            let _ = cert_update_rx.borrow_and_update();
            continue;
        }
        break;
    }

    Ok(())
}

/// 產生mini controller 的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<MiniController>` - 返回 MiniController 實例或錯誤
pub async fn mini_controller_cert(
    cert_handler: &Arc<CertificateProcess>,
    uid: Uuid,
) -> CaResult<MiniController> {
    let mini_cert: (PrivateKey, CsrCert) = CertUtils::generate_csr_with_new_key(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "miniC.chm.com",
        ["127.0.0.1", "miniC.chm.com", "mca.chm.com", uid.to_string().as_str()],
    )?;
    let mini_csr = X509Req::from_pem(&mini_cert.1)?;
    let mini_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&mini_csr, 1).await?;
    // CertUtils::save_cert("mini_controller", &mini_cert.0, &mini_sign.0)?;
    let mini_c = MiniController::new(Some(mini_cert.0), Some(mini_sign.0), cert_handler.clone());
    Ok(mini_c)
}

/// 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<()>` - 返回結果，表示操作是否成功
pub async fn ca_grpc_cert(cert_handler: &CertificateProcess, uid: Uuid) -> CaResult<()> {
    let self_ip = GlobalConfig::with(|cfg| cfg.server.host.clone());
    let ca_grpc: (PrivateKey, CsrCert) = CertUtils::generate_csr_with_new_key(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        get_local_hostname().as_str(),
        [
            "127.0.0.1",
            self_ip.as_str(),
            "ca.chm.com",
            "mca.chm.com",
            uid.to_string().as_str(),
            get_local_hostname().as_str(),
        ],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertUtils::save_cert(ID, &ca_grpc.0, &ca_grpc_sign.0)?;
    Ok(())
}

/// 產生grpc client 的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<()>` - 返回結果，表示操作是否成功
pub async fn grpc_test_cert(cert_handler: &CertificateProcess) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = CertUtils::generate_csr_with_new_key(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "test.chm.com",
        ["127.0.0.1", "test.chm.com"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertUtils::save_cert("grpc_test", &ca_grpc.0, &ca_grpc_sign.0)?;
    Ok(())
}

/// 產生一個非controller的憑證並保存到指定的目錄
pub async fn one_cert(cert_handler: &CertificateProcess) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = CertUtils::generate_csr_with_new_key(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "one.chm.com",
        ["127.0.0.1", "one.chm.com"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertUtils::save_cert("one_test", &ca_grpc.0, &ca_grpc_sign.0)?;
    Ok(())
}
/// 產生一個非controller的憑證並保存到指定的目錄
pub async fn create_new_rootca() -> CaResult<()> {
    let ca_test: (PrivateKey, CsrCert) = CertificateProcess::generate_root_ca(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "testca.chm.com",
        3650,
        // Some(b"test_password"),
        None,
        256,
    )?;
    CertUtils::save_cert("rootCA", &ca_test.0, &ca_test.1)?;
    tracing::info!("Root CA generated!");
    Ok(())
}
