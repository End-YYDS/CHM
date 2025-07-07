use dhcp_service::DhcpServiceImpl;
use dhcp_service::dhcp::dhcp_service_server::DhcpServiceServer;
use dotenv::dotenv;
use sqlx::SqlitePool;
use std::env;
use tokio::sync::watch;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://dhcp.db".to_string());
    let pool = SqlitePool::connect(&db_url).await?;
    let addr = "[::1]:50051".parse()?;
    let (reload_tx, mut reload_rx) = watch::channel(());

    loop {
        let mut rx = reload_rx.clone();
        let service = DhcpServiceImpl { pool: Some(pool.clone()) };

        println!("[gRPC] server listening on {}", addr);

        let shutdown_signal = async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("[gRPC] shutting down...");
                }
                Ok(_) = rx.changed() => {
                    println!("[gRPC] restarting...");
                }
            }
        };

        let server = Server::builder()
            .add_service(DhcpServiceServer::new(service))
            .serve_with_shutdown(addr, shutdown_signal);

        if let Err(e) = server.await {
            eprintln!("[gRPC] startup failed: {:?}", e);
        }

        if reload_rx.has_changed().unwrap_or(false) {
            println!("[gRPC] restart complete");
            let _ = reload_rx.borrow_and_update();
            continue;
        }

        break;
    }

    Ok(())
}
