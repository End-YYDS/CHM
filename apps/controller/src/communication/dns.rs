use crate::ConResult;
use chm_grpc::{
    dns::{
        dns_service_client::DnsServiceClient, AddHostRequest, DeleteHostRequest,
        EditHostnameRequest, EditIpRequest, EditUuidRequest,
    },
    tonic::{codec::CompressionEncoding, transport::Channel},
};
use chm_project_const::uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ClientDNS {
    client:  DnsServiceClient<Channel>,
    channel: Channel,
}
impl ClientDNS {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 DNS 客戶端...");
        let client = DnsServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("DNS 客戶端已建立");
        Self { client, channel }
    }
    pub fn get_client(&self) -> DnsServiceClient<Channel> {
        self.client.clone()
    }
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    pub async fn add_host(&self, hostname: String, ip: String, uuid: Uuid) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = AddHostRequest { hostname, ip, id: uuid.to_string() };
        let reply = client.add_host(req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
        Ok(reply.success)
    }
    pub async fn delete_host(&self, uuid: Uuid) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = DeleteHostRequest { id: uuid.to_string() };
        let reply =
            client.delete_host(req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
        Ok(reply.success)
    }
    pub async fn edit_uuid(&self, o_uuid: Uuid, n_uuid: Uuid) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = EditUuidRequest { id: o_uuid.to_string(), new_id: n_uuid.to_string() };
        let reply = client.edit_uuid(req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
        Ok(reply.success)
    }
    pub async fn edit_hostname(&self, uuid: Uuid, new_hostname: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = EditHostnameRequest { id: uuid.to_string(), new_hostname };
        let reply =
            client.edit_hostname(req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
        Ok(reply.success)
    }
    pub async fn edit_ip(&self, uuid: Uuid, new_ip: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = EditIpRequest { id: uuid.to_string(), new_ip };
        let reply = client.edit_ip(req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
        Ok(reply.success)
    }
}
