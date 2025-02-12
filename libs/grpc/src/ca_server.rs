use crate::common::Return;
use crate::communication::communication_server::{Communication, CommunicationServer};
use crate::communication::{Request as CommRequest, Response as CommResponse};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_health::server::health_reporter;

#[derive(Default)]
pub struct CaCommunicate {}

#[tonic::async_trait]
impl Communication for CaCommunicate {
    async fn send(&self, request: Request<CommRequest>) -> Result<Response<CommResponse>, Status> {
        println!("CA Server 收到請求: {:?}", request);
        let req = request.into_inner();
        let reply = CommResponse {
            message: format!("CA Server 收到：{}", req.message),
        };
        Ok(Response::new(reply))
    }
}

pub async fn start(addr: &str) -> Return<()> {
    let addr = addr.parse()?;
    let (mut health_reporter, health_server) = health_reporter();
    health_reporter
        .set_serving::<CommunicationServer<CaCommunicate>>()
        .await;

    println!("CA gRPC Server 正在 {} 上運行...", addr);
    Server::builder()
        .add_service(health_server)
        .add_service(CommunicationServer::new(CaCommunicate::default()))
        .serve(addr)
        .await?;
    Ok(())
}
