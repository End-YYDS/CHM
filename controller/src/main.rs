use config::Config;
use grpc::common::Return;
use grpc::controller_server::start as start_grpc_server;
#[tokio::main]
async fn main() -> Return<()> {
    let config = Config::default();
    start_grpc_server(&config.addr).await?;
    Ok(())
}
