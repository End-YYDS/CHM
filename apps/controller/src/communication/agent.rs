use crate::ConResult;
use chm_grpc::tonic::transport::Channel;

#[derive(Debug, Clone)]
pub struct ClientAgent {
    // client: AgentClient<Channel>
    channel: Channel,
}

impl ClientAgent {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 Agent 客戶端...");
        // let client = AgentClient::new(channel.clone())
        //     .accept_compressed(CompressionEncoding::Zstd)
        //     .send_compressed(CompressionEncoding::Zstd);
        tracing::info!("Agent 客戶端已建立");
        Self {
            // client,
            channel,
        }
    }
    // pub fn get_client(&self) -> AgentClient<Channel>
    // {
    //     self.client.clone()
    // }
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
    pub async fn reboot_system(&self, pc: &str) -> ConResult<bool> {
        // TODO: 需要實作重新啟動Agent
        // let mut client = self.get_client();
        // let resp = client.reboot_system(chm_grpc::agent::Empty {}).await?;
        // let reply = resp.into_inner();
        // Ok(reply.success)
        dbg!(pc);
        Ok(true)
    }
    pub async fn shutdown_system(&self, pc: &str) -> ConResult<bool> {
        // TODO: 需要實作關閉Agent
        dbg!(pc);
        Ok(true)
    }
}
