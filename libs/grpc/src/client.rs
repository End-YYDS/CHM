use crate::communication::communication_client::CommunicationClient;
use crate::communication::{Request as CommRequest, Response as CommResponse};
use tonic::transport::Channel;
use tonic::Request;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

pub struct Client {
    client: CommunicationClient<Channel>,
    health_client: HealthClient<Channel>,
}
impl Client {
    /// 連接到 gRPC 服務器
    /// # Arguments
    /// * `addr` - 服務器地址
    /// # Returns
    /// 返回一個新的 Client 實例
    pub async fn connect(addr: &str) -> crate::common::Return<Self> {
        let channel = Channel::from_shared(format!("http://{}", addr))?
            .connect()
            .await?;

        let client = CommunicationClient::new(channel.clone());
        let health_client = HealthClient::new(channel);

        Ok(Self {
            client,
            health_client,
        })
    }
    /// 發送消息
    /// # Arguments
    /// * `message` - 消息內容
    /// # Returns
    /// 返回一個 CommResponse
    pub async fn send_message(&mut self, message: &str) -> crate::common::Return<CommResponse> {
        let request = Request::new(CommRequest {
            message: message.to_string(),
        });
        let response = self.client.send(request).await?;
        Ok(response.into_inner())
    }
    /// 檢查 gRPC 伺服器健康狀態
    /// # Returns
    /// 返回健康檢查結果
    pub async fn check_health(&mut self) -> crate::common::Return<String> {
        let request = Request::new(HealthCheckRequest {
            service: "communication.Communication".to_string(),
        });

        let response = self.health_client.check(request).await?;
        let ret = match response.into_inner().status {
            0 => "UNKNOWN",
            1 => "✅ SERVING",
            2 => "❌ NOT_SERVING",
            3 => "❌ SERVICE_UNKNOWN",
            _ => "❓ Unexpected Status",
        };
        Ok(format!("Health Status: {}", ret))
    }
}
