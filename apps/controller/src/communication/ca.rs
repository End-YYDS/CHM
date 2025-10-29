use chm_grpc::{
    ca::{ca_client::CaClient, CertStatus},
    tonic::{codec::CompressionEncoding, transport::Channel},
};

use crate::ConResult;
type SignedCertificate = Vec<u8>;
type CertificateChain = Vec<Vec<u8>>;
#[derive(Debug, Clone)]
pub struct ClientCA {
    client:  CaClient<Channel>,
    channel: Channel,
}
#[allow(unused)]
impl ClientCA {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 CA 客戶端...");
        let client = CaClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("CA 客戶端已建立");
        Self { client, channel }
    }

    pub fn get_client(&self) -> CaClient<Channel> {
        self.client.clone()
    }
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    pub async fn sign_certificate(
        &self,
        csr: Vec<u8>,
        days: u32,
    ) -> ConResult<(SignedCertificate, CertificateChain)> {
        let mut client = self.get_client();
        let resp = client.sign_csr(chm_grpc::ca::CsrRequest { csr, days }).await?;
        let reply = resp.into_inner();
        Ok((reply.cert, reply.chain))
    }
    pub async fn reload_grpc(&self) -> ConResult<bool> {
        let mut client = self.get_client();
        let resp = client.reload_grpc(chm_grpc::ca::Empty {}).await?;
        let reply = resp.into_inner();
        Ok(reply.success)
    }
    pub async fn get_all_certificates(&self) -> ConResult<Vec<chm_grpc::ca::Cert>> {
        let mut client = self.get_client();
        let resp = client.list_all(chm_grpc::ca::Empty {}).await?;
        let reply = resp.into_inner();
        Ok(reply.certs)
    }
    pub async fn get_all_revoked_certificates(&self) -> ConResult<Vec<chm_grpc::ca::CrlEntry>> {
        let mut client = self.get_client();
        let resp = client.list_crl(chm_grpc::ca::Empty {}).await?;
        let reply = resp.into_inner();
        Ok(reply.certs)
    }
    pub async fn get_certificate_by_serial(
        &self,
        serial: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let mut client = self.get_client();
        let serial: String = serial.into();
        let resp = client.get(chm_grpc::ca::GetCertRequest { serial: serial.clone() }).await?;
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
        &self,
        thumbprint: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let mut client = self.get_client();
        let thumbprint: String = thumbprint.into();
        let resp = client
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
        &self,
        common_name: impl Into<String>,
    ) -> ConResult<Option<chm_grpc::ca::Cert>> {
        let mut client = self.get_client();
        let common_name: String = common_name.into();
        let resp = client
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
        &self,
        serial: impl Into<String>,
    ) -> ConResult<CertStatus> {
        let mut client = self.get_client();
        let serial: String = serial.into();
        let resp = client
            .query_cert_status(chm_grpc::ca::QueryCertStatusRequest { serial: serial.clone() })
            .await?;
        let reply = resp.into_inner().status;
        tracing::info!("憑證 {} 的狀態為 {:?}", serial, reply);
        let reply = CertStatus::try_from(reply.unwrap())?;
        Ok(reply)
    }
    pub async fn mark_certificate_as_revoked(
        &self,
        serial: impl Into<String>,
        reason: Option<impl Into<String>>,
    ) -> ConResult<bool> {
        let mut client = self.get_client();
        let serial: String = serial.into();
        let resp = client
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
