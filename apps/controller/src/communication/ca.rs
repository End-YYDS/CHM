use chm_grpc::{
    ca::{ca_client::CaClient, CertStatus},
    tonic::{codec::CompressionEncoding, transport::Channel},
};

use crate::ConResult;
type SignedCertificate = Vec<u8>;
type CertificateChain = Vec<Vec<u8>>;
#[derive(Debug)]
pub struct ClientCA {
    client: CaClient<Channel>,
}
#[allow(unused)]
impl ClientCA {
    pub fn new(channel: Channel) -> Self {
        tracing::info!("建立 CA 客戶端...");
        let client = CaClient::new(channel)
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("CA 客戶端已建立");
        Self { client }
    }

    pub fn get_client(&self) -> CaClient<Channel> {
        self.client.clone()
    }
    pub async fn sign_certificate(
        &mut self,
        csr: Vec<u8>,
        days: u32,
    ) -> ConResult<(SignedCertificate, CertificateChain)> {
        let resp = self.client.sign_csr(chm_grpc::ca::CsrRequest { csr, days }).await?;
        let reply = resp.into_inner();
        Ok((reply.cert, reply.chain))
    }
    pub async fn reload_grpc(&mut self) -> ConResult<bool> {
        let resp = self.client.reload_grpc(chm_grpc::ca::Empty {}).await?;
        let reply = resp.into_inner();
        Ok(reply.success)
    }
    pub async fn get_all_certificates(&mut self) -> ConResult<Vec<chm_grpc::ca::Cert>> {
        let resp = self.client.list_all(chm_grpc::ca::Empty {}).await?;
        let reply = resp.into_inner();
        Ok(reply.certs)
    }
    pub async fn get_certificate_by_serial(
        &mut self,
        serial: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let serial: String = serial.into();
        let resp = self.client.get(chm_grpc::ca::GetCertRequest { serial: serial.clone() }).await?;
        let reply = resp.into_inner().cert;
        match reply {
            Some(cert) => Ok(Some(cert)),
            None => {
                tracing::warn!("未找到序列號為 {} 的憑證", serial);
                Ok(None)
            }
        }
    }
    pub async fn get_certificate_by_thumbprint(
        &mut self,
        thumbprint: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let thumbprint: String = thumbprint.into();
        let resp = self
            .client
            .get_by_thumbprint(chm_grpc::ca::GetByThumprintRequest {
                thumbprint: thumbprint.clone(),
            })
            .await?;
        let reply = resp.into_inner().cert;
        match reply {
            Some(cert) => Ok(Some(cert)),
            None => {
                tracing::warn!("未找到指紋為 {} 的憑證", thumbprint);
                Ok(None)
            }
        }
    }
    pub async fn get_certificate_by_common_name(
        &mut self,
        common_name: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let common_name: String = common_name.into();
        let resp = self
            .client
            .get_by_common_name(chm_grpc::ca::GetByCommonNameRequest { name: common_name.clone() })
            .await?;
        let reply = resp.into_inner().cert;
        match reply {
            Some(cert) => Ok(Some(cert)),
            None => {
                tracing::warn!("未找到通用名稱為 {} 的憑證", common_name);
                Ok(None)
            }
        }
    }
    pub async fn get_cert_status_by_serial(
        &mut self,
        serial: impl Into<String>,
    ) -> ConResult<CertStatus> {
        let serial: String = serial.into();
        let resp = self
            .client
            .query_cert_status(chm_grpc::ca::QueryCertStatusRequest { serial: serial.clone() })
            .await?;
        let reply = resp.into_inner().status;
        tracing::info!("憑證 {} 的狀態為 {:?}", serial, reply);
        let reply = CertStatus::try_from(reply.unwrap())?;
        Ok(reply)
    }
    pub async fn mark_certificate_as_revoked(
        &mut self,
        serial: impl Into<String>,
        reason: Option<impl Into<String>>,
    ) -> ConResult<bool> {
        let serial: String = serial.into();
        let resp = self
            .client
            .mark_cert_revoked(chm_grpc::ca::MarkCertRevokedRequest {
                serial: serial.clone(),
                reason: reason.map(Into::into),
            })
            .await?;
        let reply = resp.into_inner().success;
        if reply {
            tracing::info!("憑證 {} 已成功標記為撤銷", serial);
        } else {
            tracing::warn!("憑證 {} 標記為撤銷失敗", serial);
        }
        Ok(reply)
    }
}
