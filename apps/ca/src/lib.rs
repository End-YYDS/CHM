// pub mod grpc {
//     include!("generated/ca.rs");
// }

pub mod cert;
pub mod config;
pub mod connection;
pub mod globals;
pub mod mini_controller;
use grpc::{ca::*, tonic, tonic_health};
use openssl::x509::X509;

use std::{net::SocketAddr, sync::Arc};
use tonic::{
    transport::{Identity, ServerTlsConfig},
    Request, Status,
};
use tonic_health::server::health_reporter;

use crate::{cert::process::CertificateProcess, connection::MyCa};
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
            .is_controller_cert(&x509)
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
    let svc = ca_server::CaServer::with_interceptor(
        MyCa {
            cert: cert_handler.clone(),
        },
        middleware(cert_handler.clone()),
    );
    println!("gRPC server listening on {}", addr);
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl-C");
        println!("收到CtrlC,開始關閉gRPC...");
        health_reporter
            .set_not_serving::<ca_server::CaServer<MyCa>>()
            .await;
    };
    tonic::transport::Server::builder()
        .tls_config(tls)?
        .add_service(svc)
        .add_service(health_service)
        .serve_with_shutdown(addr, shutdown_signal)
        .await?;
    Ok(())
}
