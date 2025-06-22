// pub mod grpc {
//     include!("generated/ca.rs");
// }

pub mod cert;
pub mod config;
pub mod connection;
pub mod globals;
pub mod mini_controller;
use grpc::{ca::*, tonic, tonic_health};
use openssl::x509::{X509Req, X509};
use tokio::sync::watch;

use std::{fs, io::Write, net::SocketAddr, path::Path, sync::Arc};
use tonic::{
    transport::{Identity, ServerTlsConfig},
    Request, Status,
};
use tonic_health::server::health_reporter;

use crate::{
    cert::process::CertificateProcess, connection::MyCa, globals::GlobalConfig,
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

/// 建立一個 gRPC 的 CRL 檢查攔截器
/// # 參數
/// * `cert_handler`: 憑證處理器，用於檢查 CRL
/// # 回傳
/// * `impl Fn(Request<()>) -> Result<Request<()>, Status>`: 返回一個攔截器函數
fn middleware(
    cert_handler: Arc<CertificateProcess>,
    controller_args: (String, String),
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone + Send + Sync + 'static {
    move |req: Request<()>| {
        let metadata = req.metadata();
        let peer_der_vec = req
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
        let peer_slice: &[tonic::transport::CertificateDer] = peer_der_vec.as_ref().as_slice();
        let leaf = peer_slice
            .first()
            .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;
        let x509 = X509::from_der(leaf)
            .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))?;
        // 檢查是否被吊銷之後，在檢查是否來自controller的請求，其他一律擋掉
        // if !cert_handler
        //     .get_crl()
        //     .after_connection_cert_check(peer_certs_slice)
        // {
        //     Err(Status::permission_denied("Certificate was Revoked"))
        // } else {
        //     Ok(req)
        // }

        if let Some(val) = metadata.get("crl") {
            // 檢查是否有帶上 crl 的 metadata
            let need_crl = val.to_str().unwrap_or("false") == "true";
            if need_crl {
                unimplemented!("CRL check not implemented yet");
                // 回傳CRL list
            }
        }

        let is_ctrl = cert_handler
            .is_controller_cert(&x509, controller_args.clone())
            .map_err(|e| Status::internal(format!("Controller check failed: {}", e)))?;
        if !is_ctrl {
            return Err(Status::permission_denied("Only controller cert is allowed"));
        }

        Ok(req) //TODO 暫時不檢查 CRL
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
        let svc = ca_server::CaServer::with_interceptor(
            MyCa {
                cert: cert_handler.clone(),
                reloader: cert_update_tx.clone(),
            },
            middleware(cert_handler.clone(), controller_args),
        );
        println!("gRPC server listening on {}", addr);
        let server = tonic::transport::Server::builder()
            .tls_config(tls)?
            .add_service(svc)
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
    CertificateProcess::save_cert("ca_grpc", ca_grpc_sign.0, ca_grpc.0)?;
    Ok(())
}

/// 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
/// # 參數
/// * `cert_handler` - 用於簽署憑證的 CertificateProcess 處理器
/// # 回傳
/// * `CaResult<()>` - 返回結果，表示操作是否成功
#[allow(unused)]
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
    CertificateProcess::save_cert("grpc_test", ca_grpc_sign.0, ca_grpc.0)?;
    Ok(())
}
