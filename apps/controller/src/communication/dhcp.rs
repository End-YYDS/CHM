use crate::ConResult;
use chm_grpc::{
    dhcp::{dhcp_service_client::DhcpServiceClient, Zone},
    tonic::transport::Channel,
};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ClientDhcp {
    client: DhcpServiceClient<Channel>,
}

impl ClientDhcp {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 DHCP 客戶端...");
        let client = DhcpServiceClient::new(channel);
        tracing::info!("DHCP 客戶端已建立");
        Self { client }
    }
    pub fn get_client(&self) -> DhcpServiceClient<Channel> {
        self.client.clone()
    }
    pub async fn create_zone(&self, zone_name: String, vni: i32, cidr: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::CreateZoneRequest { zone_name, vni, cidr };
        let response = client.create_zone(request).await?.into_inner();
        let ret = response.message.contains("successfully");
        Ok(ret)
    }
    pub async fn allocate_ip(&self, zone_name: String) -> ConResult<String> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::AllocateIpRequest { zone_name };
        let response = client.allocate_ip(request).await?.into_inner();
        Ok(response.ip)
    }
    pub async fn release_ip(&self, zone_name: String, ip: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::ReleaseIpRequest { zone_name, ip };
        let response = client.release_ip(request).await?.into_inner();
        let ret = response.message.contains("released");
        Ok(ret)
    }
    pub async fn delete_zone(&self, zone_name: String) -> ConResult<bool> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::DeleteZoneRequest { zone_name };
        let response = client.delete_zone(request).await?.into_inner();
        let ret = response.message.contains("deleted");
        Ok(ret)
    }
    pub async fn list_zones(&self) -> ConResult<Vec<Zone>> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::Empty {};
        let response = client.list_zones(request).await?.into_inner();
        Ok(response.zones)
    }
    pub async fn list_available_ips(&self, zone_name: String) -> ConResult<Vec<IpAddr>> {
        let mut client = self.get_client();
        let request = chm_grpc::dhcp::ZoneIdentifier { zone_name };
        let response = client.list_available_ips(request).await?.into_inner();
        let ips: Vec<IpAddr> =
            response.ips.into_iter().filter_map(|ip_str| ip_str.parse::<IpAddr>().ok()).collect();
        Ok(ips)
    }
}
