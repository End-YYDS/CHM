use grpc::common::Return;
use grpc::controller_server::start as start_grpc_server;
use plugin_system::plugin_system_rest_server_handle;
#[actix_web::main]
async fn main() -> Return<()> {
    // console_subscriber::init();
    let cmg = config::get_config_manager(false);
    let grcp_service_ip = cmg.get_grpc_service_ip("controller");
    let rest_service_ip = cmg.get_rest_service_ip();
    let grpc_handle = tokio::spawn(async move {
        start_grpc_server(grcp_service_ip)
            .await
            .expect("Failed to start gRPC server");
    });
    println!("Http Server 正在 {} 上運行...", &rest_service_ip);
    // let http_server = HttpServer::new(|| App::new().service(restful::rest_service()))
    //     .bind(config.addr)?
    //     .run();
    let http_server = plugin_system_rest_server_handle().await?;
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        println!("開始關閉服務...");
    };
    tokio::select! {
        res = grpc_handle => {
            println!("gRPC server terminated: {:?}", res);
        }
        res = http_server => {
            println!("HTTP server terminated: {:?}", res);
        }
        _ = ctrl_c => {
            println!("Ctrl+C received");
        }
    }
    println!("所有服務已關閉");
    Ok(())
}
