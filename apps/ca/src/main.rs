use config::get_config_manager;
use grpc::ca_server::start as start_ca_server;
use grpc::common::Return;
#[tokio::main]
async fn main() -> Return<()> {
    let cmg = get_config_manager(None);
    start_ca_server(cmg).await?;
    Ok(())
}
