// #[cfg(all(feature = "client", feature = "server"))]
// compile_error!("features \"client\" and \"server\" cannot be enabled at the same time. Please enable only one.");
use tonic::{Request, Response, Status};
pub mod communication {
    include!("generated/communication.rs");
}
use communication::communication_server::Communication;
use communication::{Request as CommRequest, Response as CommResponse};

#[derive(Default)]
pub struct Communicate {}

#[tonic::async_trait]
impl Communication for Communicate {
    async fn send(&self, request: Request<CommRequest>) -> Result<Response<CommResponse>, Status> {
        println!("收到請求: {:?}", request);
        let req = request.into_inner();
        let reply = CommResponse {
            message: format!("Server 收到：{}", req.message),
        };
        Ok(Response::new(reply))
    }
}
#[cfg(feature = "client")]
pub mod client {
    use crate::communication::communication_client::CommunicationClient;
    use crate::communication::{Request as CommRequest, Response as CommResponse};
    use tonic::Request;

    /// 發送訊息到 gRPC 服務
    ///
    /// # 參數
    /// - `addr`: 服務的位址，例如 "127.0.0.1:50051" 或 "[::1]:50051"
    /// - `message`: 要傳送的訊息內容
    ///
    /// # 回傳
    /// 回傳 gRPC 服務回應的 `CommResponse`
    pub async fn send_message(
        addr: &str,
        message: &str,
    ) -> Result<CommResponse, Box<dyn std::error::Error>> {
        // 如果需要強制使用 HTTP，這裡建構完整的 endpoint 字串
        let endpoint = format!("http://{}", addr);
        let mut client = CommunicationClient::connect(endpoint).await?;
        let request = Request::new(CommRequest {
            message: message.to_string(),
        });
        let response = client.send(request).await?;
        Ok(response.into_inner())
    }
}

#[cfg(feature = "server")]
pub mod server {
    use crate::communication::communication_server::CommunicationServer;
    use crate::Communicate;
    use tonic::transport::Server;

    pub async fn start(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let addr = addr.parse()?;
        let service = Communicate::default();
        println!("gRPC Server 正在 {} 上運行...", addr);
        Server::builder()
            .add_service(CommunicationServer::new(service))
            .serve(addr)
            .await?;
        Ok(())
    }
}
