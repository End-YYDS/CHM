use actix_web::{App, HttpServer};
use config::Config;
use grpc::common::Return;
use grpc::controller_server::start as start_grpc_server;
mod restful;
#[actix_web::main]
async fn main() -> Return<()> {
    console_subscriber::init();
    let mut config = Config::default();
    let grpc_config = config.clone();
    let grpc_handle = tokio::spawn(async move {
        start_grpc_server(&grpc_config)
            .await
            .expect("Failed to start gRPC server");
    });
    config.set_port(8080);
    println!("Http Server 正在 {} 上運行...", config.addr);
    let http_server = HttpServer::new(|| App::new().service(restful::rest_service()))
        .bind(config.addr)?
        .run();
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
