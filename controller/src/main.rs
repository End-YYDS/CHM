use config::Config;
use grpc::server::start as start_grpc_server;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new();
    start_grpc_server(&config.addr).await?;
    Ok(())
}
