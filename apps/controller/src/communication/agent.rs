use crate::ConResult;
use chm_grpc::{
    agent::{
        agent_file_service_client::AgentFileServiceClient,
        agent_info_service_client::AgentInfoServiceClient,
        agent_service_client::AgentServiceClient, AgentCommand, CommandRequest,
    },
    tonic::{codec::CompressionEncoding, transport::Channel},
};
use chm_project_const::uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ClientAgent {
    m_client: AgentServiceClient<Channel>,
    f_client: AgentFileServiceClient<Channel>,
    i_client: AgentInfoServiceClient<Channel>,
    channel:  Channel,
    uuid:     Uuid,
    hostname: String,
}

impl ClientAgent {
    pub fn new_with_meta(
        channel: Channel,
        uuid: chm_project_const::uuid::Uuid,
        hostname: String,
    ) -> Self {
        tracing::debug!("建立 Agent-{hostname} 客戶端...");
        let m_client = AgentServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        let f_client = AgentFileServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        let i_client = AgentInfoServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("Agent-{hostname} 客戶端已建立");
        Self { m_client, f_client, i_client, channel, uuid, hostname }
    }
    pub fn get_m_client(&self) -> AgentServiceClient<Channel> {
        self.m_client.clone()
    }
    pub fn get_f_client(&self) -> AgentFileServiceClient<Channel> {
        self.f_client.clone()
    }
    pub fn get_i_client(&self) -> AgentInfoServiceClient<Channel> {
        self.i_client.clone()
    }
    #[inline]
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    #[inline]
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
    #[inline]
    pub fn hostname(&self) -> &str {
        self.hostname.as_str()
    }
    pub async fn reboot_system(&self) -> ConResult<bool> {
        let mut client = self.get_m_client();
        let resp = client
            .execute_command(CommandRequest {
                command:  AgentCommand::Reboot as i32,
                argument: None,
            })
            .await
            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        dbg!(resp);
        Ok(true)
    }
    pub async fn shutdown_system(&self) -> ConResult<bool> {
        let mut client = self.get_m_client();
        let resp = client
            .execute_command(CommandRequest {
                command:  AgentCommand::Shutdown as i32,
                argument: None,
            })
            .await
            .inspect_err(|e| tracing::error!(?e))?
            .into_inner();
        dbg!(resp);
        Ok(true)
    }
}
