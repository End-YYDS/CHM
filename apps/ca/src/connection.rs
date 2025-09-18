use std::sync::Arc;

use crate::cert::process::CertificateProcess;
use chm_cert_utils::CertUtils;
use chm_grpc::{
    ca::{ca_server::Ca, *},
    tonic,
};
use openssl::x509::X509Req;
use tonic::{Request, Response, Status};

use crate::cert::store::{Cert as StoreCert, CertStatus as StoreStatus, CrlEntry as StoreCrlEntry};
use chm_grpc::ca::{Cert as GrpcCert, CertStatus as GrpcStatus, CrlEntry as GrpcCrlEntry};

impl From<StoreCert> for GrpcCert {
    fn from(c: StoreCert) -> Self {
        GrpcCert {
            serial:      c.serial.unwrap_or_default(),
            subject_cn:  c.subject_cn.unwrap_or_default(),
            subject_dn:  c.subject_dn.unwrap_or_default(),
            issuer:      c.issuer.unwrap_or_default(),
            issued_date: Some(CertUtils::to_prost_timestamp(&c.issued_date)),
            expiration:  Some(CertUtils::to_prost_timestamp(&c.expiration)),
            thumbprint:  c.thumbprint.unwrap_or_default(),
            status:      match c.status {
                StoreStatus::Valid => GrpcStatus::Valid as i32,
                StoreStatus::Revoked => GrpcStatus::Revoked as i32,
            },
        }
    }
}

impl From<StoreCrlEntry> for GrpcCrlEntry {
    fn from(c: StoreCrlEntry) -> Self {
        GrpcCrlEntry {
            cert_serial: c.cert_serial.unwrap_or_default(),
            revoked_at:  Some(CertUtils::to_prost_timestamp(&c.revoked_at)),
            reason:      c.reason.unwrap_or_default(),
        }
    }
}

/// gRPC CA 實現
pub struct MyCa {
    /// 憑證處理器
    pub cert:     Arc<CertificateProcess>,
    pub reloader: tokio::sync::watch::Sender<()>,
}

#[tonic::async_trait]
impl Ca for MyCa {
    /// 處理 CSR 請求，簽署憑證並返回
    /// # 參數
    /// * `req`: 包含 CSR 和有效天數的請求
    /// # 回傳
    /// * `Result<Response<CsrResponse>, Status>`:
    ///   返回簽署的憑證和鏈，或錯誤狀態
    async fn sign_csr(&self, req: Request<CsrRequest>) -> Result<Response<CsrResponse>, Status> {
        let temp = req.into_parts();
        let debug = cfg!(debug_assertions);
        if debug {
            dbg!(&temp);
        }

        let CsrRequest { csr, days } = temp.2;
        let csr = X509Req::from_der(&csr)
            .or_else(|_| X509Req::from_pem(&csr))
            .map_err(|e| Status::invalid_argument(format!("Invalid CSR: {e}")))?;
        let (leaf, chain) = self.cert.sign_csr(&csr, days).await.map_err(|e| {
            if debug {
                tracing::error!("Sign error: {e}");
            }
            Status::internal(format!("Sign error: {e}"))
        })?;
        Ok(Response::new(CsrResponse { cert: leaf, chain }))
    }
    /// 重新加載 gRPC 配置
    /// # 參數
    /// * `_req`: 空請求
    /// # 回傳
    /// * `Result<Response<ReloadResponse>, Status>`: 返回是否成功重新加載
    async fn reload_grpc(&self, _req: Request<Empty>) -> Result<Response<ReloadResponse>, Status> {
        if let Err(e) = self.reloader.send(()) {
            return Err(Status::internal(format!("Reloader error: {e}")));
        }
        Ok(Response::new(ReloadResponse { success: true }))
    }
    /// 列出所有憑證
    /// # 參數
    /// * `_req`: 空請求
    /// # 回傳
    /// * `Result<Response<ListAllCertsResponse>, Status>`: 返回所有憑證的列表
    async fn list_all(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<ListAllCertsResponse>, Status> {
        let certs = self
            .cert
            .get_store()
            .list_all()
            .await
            .map_err(|e| Status::internal(format!("Failed to list all certs: {e}")))?;
        let grpc_certs: Vec<Cert> = certs.into_iter().map(Into::into).collect();
        Ok(Response::new(ListAllCertsResponse { certs: grpc_certs }))
    }

    async fn list_crl(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ListAllCrlResponse>, Status> {
        let certs = self
            .cert
            .get_store()
            .list_crl()
            .await
            .map_err(|e| Status::internal(format!("Failed to list all revoked certs: {e}")))?;
        let grpc_certs: Vec<CrlEntry> = certs.into_iter().map(Into::into).collect();
        Ok(Response::new(ListAllCrlResponse { certs: grpc_certs }))
    }

    async fn get(&self, req: Request<GetCertRequest>) -> Result<Response<GetCertResponse>, Status> {
        let serial = req.into_inner().serial;
        let cert = self
            .cert
            .get_store()
            .get(&serial)
            .await
            .map_err(|e| Status::internal(format!("Failed to get cert: {e}")))?
            .ok_or_else(|| Status::not_found(format!("Cert not found: {serial}")))?;
        Ok(Response::new(GetCertResponse { cert: Some(cert.into()) }))
    }
    async fn get_by_thumbprint(
        &self,
        req: Request<GetByThumprintRequest>,
    ) -> Result<Response<GetByThumprintResponse>, Status> {
        let thumbprint = req.into_inner().thumbprint;
        let cert = self
            .cert
            .get_store()
            .get_by_thumbprint(&thumbprint)
            .await
            .map_err(|e| Status::internal(format!("Failed to get cert by thumbprint: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!("Cert not found for thumbprint: {thumbprint}"))
            })?;
        Ok(Response::new(GetByThumprintResponse { cert: Some(cert.into()) }))
    }
    async fn get_by_common_name(
        &self,
        req: Request<GetByCommonNameRequest>,
    ) -> Result<Response<GetByCommonNameResponse>, Status> {
        let common_name = req.into_inner().name;
        let cert = self
            .cert
            .get_store()
            .get_by_common_name(&common_name)
            .await
            .map_err(|e| Status::internal(format!("Failed to get cert by common name: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!("Cert not found for common name: {common_name}"))
            })?;
        Ok(Response::new(GetByCommonNameResponse { cert: Some(cert.into()) }))
    }
    async fn query_cert_status(
        &self,
        req: Request<QueryCertStatusRequest>,
    ) -> Result<Response<QueryCertStatusResponse>, Status> {
        let serial = req.into_inner().serial;
        let status = self
            .cert
            .get_store()
            .query_cert_status(&serial)
            .await
            .map_err(|e| Status::internal(format!("Failed to query cert status: {e}")))?
            .ok_or_else(|| Status::not_found(format!("Cert not found: {serial}")))?;
        Ok(Response::new(QueryCertStatusResponse {
            status: match status {
                StoreStatus::Valid => Some(GrpcStatus::Valid as i32),
                StoreStatus::Revoked => Some(GrpcStatus::Revoked as i32),
            },
        }))
    }
    async fn mark_cert_revoked(
        &self,
        req: Request<MarkCertRevokedRequest>,
    ) -> Result<Response<MarkCertRevokedResponse>, Status> {
        let req = req.into_inner();
        let serial = req.serial;
        let reason = req.reason;
        self.cert
            .get_store()
            .mark_cert_revoked(&serial, reason)
            .await
            .map_err(|e| Status::internal(format!("Failed to mark cert as revoked: {e}")))?;
        self.cert
            .get_crl()
            .reload_crl()
            .await
            .map_err(|e| Status::internal(format!("Failed reload CRL: {e}")))?;
        Ok(Response::new(MarkCertRevokedResponse { success: true }))
    }
}
