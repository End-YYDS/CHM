use std::sync::Arc;

use openssl::x509::X509Req;
use tonic::{Request, Response, Status};

use crate::{
    grpc::{ca_server::Ca, CsrRequest, CsrResponse},
    Certificate,
};

pub struct MyCa {
    pub cert: Arc<Certificate>,
}

#[tonic::async_trait]
impl Ca for MyCa {
    async fn sign_csr(&self, req: Request<CsrRequest>) -> Result<Response<CsrResponse>, Status> {
        if !self
            .cert
            .get_crl()
            .after_connection_cert_check(req.peer_certs())
        {
            return Err(Status::internal("Certificate was Revoked"));
        }
        let temp = req.into_parts();
        // dbg!(&temp);
        let CsrRequest { csr, days } = temp.2;
        let csr = X509Req::from_der(&csr)
            .or_else(|_| X509Req::from_pem(&csr))
            .map_err(|e| Status::invalid_argument(format!("Invalid CSR: {}", e)))?;
        let (leaf, chain) = self
            .cert
            .sign_csr(&csr, days)
            .map_err(|e| Status::internal(format!("Sign error: {}", e)))?;
        Ok(Response::new(CsrResponse { cert: leaf, chain }))
    }
}
