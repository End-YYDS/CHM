use grpc::common::Return;
use grpc::controller_server::start as start_grpc_server;
use plugin_system::plugin_system_rest_server_handle;
#[actix_web::main]
async fn main() -> Return<()> {
    // console_subscriber::init();
    let cmg = config::get_config_manager(false);
    let grcp_service_ip = cmg.get_grpc_service_ip("controller");
    let grpc_handle = tokio::spawn(async move {
        start_grpc_server(grcp_service_ip)
            .await
            .expect("Failed to start gRPC server");
    });
    let http_server = plugin_system_rest_server_handle(cmg).await?;
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
    };
    tokio::select! {
        res = grpc_handle => {
            println!("gRPC server terminated: {:?}", res);
        }
        res = http_server => {
            println!("HTTP server terminated: {:?}", res);
        }
        _ = ctrl_c => {}
    }
    println!("所有服務已關閉");
    Ok(())
}
