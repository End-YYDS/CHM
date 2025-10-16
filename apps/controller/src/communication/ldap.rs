#![allow(dead_code)]
use chm_grpc::{ldap::ldap_service_client::LdapServiceClient, tonic::transport::Channel};

#[derive(Debug, Clone)]
pub struct ClientLdap {
    client: LdapServiceClient<Channel>,
}

impl ClientLdap {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 LDAP 客戶端...");
        let client = LdapServiceClient::new(channel);
        tracing::info!("LDAP 客戶端已建立");
        Self { client }
    }

    pub fn get_client(&self) -> LdapServiceClient<Channel> {
        self.client.clone()
    }
}
