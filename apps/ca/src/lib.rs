// pub mod grpc {
//     include!("generated/ca.rs");
// }

pub mod cert;
pub mod config;
pub mod connection;
pub mod globals;
pub mod mini_controller;
use futures::{future::BoxFuture, FutureExt};
use grpc::{
    ca::{ca_server::CaServer, *},
    crl::crl_server,
    tonic, tonic_health,
};
use openssl::x509::{X509Req, X509};
use tokio::sync::watch;
use tonic_async_interceptor::async_interceptor;
use tower::ServiceBuilder;

use std::{fs, io::Write, net::SocketAddr, path::Path, sync::Arc};
use tonic::{
    transport::{Identity, ServerTlsConfig},
    Request, Status,
};
use tonic_health::server::health_reporter;

use crate::{
    cert::{crl::CrlList, process::CertificateProcess},
    connection::MyCa,
    globals::GlobalConfig,
    mini_controller::MiniController,
};
/// 定義一個簡化的結果類型，用於返回結果或錯誤
pub type CaResult<T> = Result<T, Box<dyn std::error::Error>>;
/// 定義已經簽署的憑證類型
pub type SignedCert = Vec<u8>;
/// 定義憑證鏈類型，包含已簽署的憑證和 CA 憑證
pub type ChainCerts = Vec<SignedCert>;
/// 定義私鑰類型
pub type PrivateKey = Vec<u8>;
/// 定義 CSR 憑證類型
pub type CsrCert = Vec<u8>;
type CheckFuture = BoxFuture<'static, Result<Request<()>, Status>>;

fn get_ssl_info(req: &Request<()>) -> CaResult<(X509, String)> {
    let peer_der_vec = req
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
    let peer_slice: &[tonic::transport::CertificateDer] = peer_der_vec.as_ref().as_slice();
    let leaf = peer_slice
        .first()
        .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;
    let x509 = X509::from_der(leaf)
        .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))?;
    let serial = CertificateProcess::cert_serial_sha256(&x509)
        .map_err(|e| Status::internal(format!("Serial sha256 failed: {}", e)))?;
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
    let (x509, _) =
        get_ssl_info(&req).map_err(|e| Status::internal(format!("SSL info failed: {}", e)))?;
    let is_ctrl = cert_handler
        .is_controller_cert(&x509, controller_args.clone())
        .map_err(|e| Status::internal(format!("Controller check failed: {}", e)))?;
    if !is_ctrl {
        return Err(Status::permission_denied("Only controller cert is allowed"));
    }

    Ok(req)
}
async fn check_revoke(
    cert_handler: Arc<CertificateProcess>,
    req: Request<()>,
) -> Result<Request<()>, Status> {
    let (_, serial) =
        get_ssl_info(&req).map_err(|e| Status::internal(format!("SSL info failed: {}", e)))?;
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
/// * `Result<(), Box<dyn std::error::Error>>`: 返回結果，成功時為 Ok，失敗時為 Err
pub async fn start_grpc(
    addr: SocketAddr,
    cert_handler: Arc<CertificateProcess>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cert_update_tx, mut cert_update_rx) = watch::channel(());
    loop {
        let mut rx = cert_update_rx.clone();
        // 設定 TLS
        let (key, cert) = CertificateProcess::cert_from_path("ca_grpc", None)?;
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new().identity(identity).client_ca_root(
            tonic::transport::Certificate::from_pem(cert_handler.get_ca_cert().to_pem()?),
        );
        // ----------
        // 啟動健康檢查服務
        let (health_reporter, health_service) = health_reporter();
        health_reporter
            .set_serving::<ca_server::CaServer<MyCa>>()
            .await;
        // ----------
        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("[gRPC] 收到 Ctrl-C，開始關閉...");
                    }
                    Ok(_) = rx.changed() => {
                        println!("[gRPC] 憑證更新，開始重新啟動 gRPC...");
                    }
                }
                health_reporter
                    .set_not_serving::<ca_server::CaServer<MyCa>>()
                    .await;
            }
        };

        let controller_args = {
            let lock = GlobalConfig::read().await;
            (
                lock.settings.controller.serial.clone(),
                lock.settings.controller.fingerprint.clone(),
            )
        };
        let ca_layer = async_interceptor(make_ca_middleware(
            cert_handler.clone(),
            controller_args.clone(),
        ));
        let ca_svc = ServiceBuilder::new()
            .layer(ca_layer)
            .service(CaServer::new(MyCa {
                cert: cert_handler.clone(),
                reloader: cert_update_tx.clone(),
            }));
        let crl_layer = async_interceptor(make_crl_middleware(cert_handler.clone()));
        let crl_svc = ServiceBuilder::new()
            .layer(crl_layer)
            .service(crl_server::CrlServer::new(CrlList {
                cert: cert_handler.clone(),
            }));
        println!("gRPC server listening on {}", addr);
        let server = tonic::transport::Server::builder()
            .tls_config(tls)?
            .add_service(ca_svc)
            .add_service(crl_svc)
            .add_service(health_service)
            .serve_with_shutdown(addr, shutdown_signal);
        if let Err(e) = server.await {
            eprintln!("[gRPC] 啟動失敗: {:?}", e);
        }
        if cert_update_rx.has_changed().unwrap_or(false) {
            println!("[gRPC] 重啟完成，重新載入新憑證並啟動服務");
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
pub async fn mini_controller_cert(cert_handler: &CertificateProcess) -> CaResult<MiniController> {
    let mini_cert: (PrivateKey, CsrCert) = CertificateProcess::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "miniC.example.com",
        &["127.0.0.1"],
    )?;
    let key = Path::new("certs").join("mini_controller.key");
    let mut f = fs::File::create(key)?;
    f.write_all(mini_cert.0.as_slice())?;
    let mini_csr = X509Req::from_pem(&mini_cert.1)?;
    let mini_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&mini_csr, 365).await?;
    let mini_c = mini_controller::MiniController::new(Some(mini_sign.0), Some(mini_cert.0));
    mini_c.save_cert("mini_controller.pem")?;
    Ok(mini_c)
}

/// 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<()>` - 返回結果，表示操作是否成功
pub async fn ca_grpc_cert(cert_handler: &CertificateProcess) -> CaResult<()> {
    let ca_grpc: (PrivateKey, CsrCert) = CertificateProcess::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "ca.example.com",
        &["127.0.0.1"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertificateProcess::save_cert("ca_grpc", ca_grpc.0, ca_grpc_sign.0)?;
    Ok(())
}

/// 產生grpc client 的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<()>` - 返回結果，表示操作是否成功
pub async fn grpc_test_cert(cert_handler: &CertificateProcess) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = CertificateProcess::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "test.example.com",
        &["127.0.0.1"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertificateProcess::save_cert("grpc_test", ca_grpc.0, ca_grpc_sign.0)?;
    Ok(())
}

/// 產生一個非controller的憑證並保存到指定的目錄
pub async fn one_cert(cert_handler: &CertificateProcess) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = CertificateProcess::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "one.example.com",
        &["127.0.0.1"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365).await?;
    CertificateProcess::save_cert("one_test", ca_grpc.0, ca_grpc_sign.0)?;
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
        "testca.example.com",
        3650,
        // Some(b"test_password"),
        None,
        256,
    )?;
    CertificateProcess::save_cert("test_root_ca", ca_test.0, ca_test.1)?;
    println!("Root CA generated!");
    Ok(())
}
