use ca::*;
use config::get_config_manager;
use tonic::transport::Server;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmg = get_config_manager(None);
    let ca_passwd = rpassword::prompt_password("Enter CA passphrase: ")?;
    let cert = Certificate::load(cmg.get_rootca_path(), cmg.get_rootca_key_path(), ca_passwd)?;
    let svc = grpc::ca_server::CaServer::new(MyCa { cert });
    let addr = cmg.get_grpc_service_ip("ca").parse()?;
    println!("CA gRPC Server listening on {}", addr);
    Server::builder().add_service(svc).serve(addr).await?;
    Ok(())
}
