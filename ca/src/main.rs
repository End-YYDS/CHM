use config::Config;
use grpc::ca_server::start as start_ca_server;
use grpc::common::Return;
#[tokio::main]
async fn main() -> Return<()> {
    let config = Config::new("[::1]:50052");
    start_ca_server(&config).await?;
    Ok(())
}
