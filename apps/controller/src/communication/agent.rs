use crate::ConResult;
use chm_grpc::{
    agent::{
        agent_file_service_client::AgentFileServiceClient,
        agent_info_service_client::AgentInfoServiceClient,
        agent_service_client::AgentServiceClient, CommandRequest,
    },
    tonic::{codec::CompressionEncoding, transport::Channel},
};

#[derive(Debug, Clone)]
pub struct ClientAgent {
    m_client: AgentServiceClient<Channel>,
    f_client: AgentFileServiceClient<Channel>,
    i_client: AgentInfoServiceClient<Channel>,
    channel:  Channel,
}

impl ClientAgent {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 Agent 客戶端...");
        let m_client = AgentServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        let f_client = AgentFileServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        let i_client = AgentInfoServiceClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("Agent 客戶端已建立");
        Self { m_client, f_client, i_client, channel }
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
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    pub async fn reboot_system(&self, pc: &str) -> ConResult<bool> {
        // TODO: 需要實作重新啟動Agent
        let mut client = self.get_m_client();
        let resp = client
            .execute_command(CommandRequest { command: "reboot".to_string(), argument: None })
            .await?
            .into_inner();
        dbg!(resp);
        dbg!(pc);
        Ok(true)
    }
    pub async fn shutdown_system(&self, pc: &str) -> ConResult<bool> {
        // TODO: 需要實作關閉Agent
        let mut client = self.get_m_client();
        let resp = client
            .execute_command(CommandRequest { command: "shutdown".to_string(), argument: None })
            .await?
            .into_inner();
        dbg!(resp);
        dbg!(pc);
        Ok(true)
    }
}
