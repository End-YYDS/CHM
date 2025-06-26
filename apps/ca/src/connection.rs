use std::sync::Arc;

use openssl::x509::X509Req;
use tonic::{Request, Response, Status};

use grpc::{
    ca::{ca_server::Ca, *},
    tonic,
};

use crate::{cert::process::CertificateProcess, config::is_debug};
/// gRPC CA 實現
pub struct MyCa {
    /// 憑證處理器
    pub cert: Arc<CertificateProcess>,
    pub reloader: tokio::sync::watch::Sender<()>,
}

#[tonic::async_trait]
impl Ca for MyCa {
    /// 處理 CSR 請求，簽署憑證並返回
    /// # 參數
    /// * `req`: 包含 CSR 和有效天數的請求
    /// # 回傳
    /// * `Result<Response<CsrResponse>, Status>`: 返回簽署的憑證和鏈，或錯誤狀態
    async fn sign_csr(&self, req: Request<CsrRequest>) -> Result<Response<CsrResponse>, Status> {
        let temp = req.into_parts();
        let debug = is_debug();
        if debug {
            dbg!(&temp);
        }

        let CsrRequest { csr, days } = temp.2;
        let csr = X509Req::from_der(&csr)
            .or_else(|_| X509Req::from_pem(&csr))
            .map_err(|e| Status::invalid_argument(format!("Invalid CSR: {}", e)))?;
        let (leaf, chain) = self.cert.sign_csr(&csr, days).await.map_err(|e| {
            if debug {
                eprintln!("Sign error: {e}");
            }
            Status::internal(format!("Sign error: {}", e))
        })?;
        Ok(Response::new(CsrResponse { cert: leaf, chain }))
    }
    async fn reload_ca(
        &self,
        _req: Request<grpc::ca::Empty>,
    ) -> Result<Response<ReloadResponse>, Status> {
        if let Err(e) = self.reloader.send(()) {
            return Err(Status::internal(format!("Reloader error: {}", e)));
        }
        Ok(Response::new(ReloadResponse { success: true }))
    }
}
//TODO: 這裡添加更多CA gRPC方法的實現
