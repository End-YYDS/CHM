use grpc::server::start as start_grpc_server;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051";
    start_grpc_server(addr).await?;
    Ok(())
}
