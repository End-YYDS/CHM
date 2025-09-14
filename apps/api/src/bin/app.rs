use actix_web::{middleware, middleware::Logger, web, App, HttpServer};
use api_server::configure_app;
use chm_grpc::{restful::restful_service_client::RestfulServiceClient, tonic::transport::Channel};
use tracing_subscriber::EnvFilter;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AppState {
    gclient: RestfulServiceClient<Channel>,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    let grpc_client = RestfulServiceClient::connect("http://127.0.0.1:50052").await?; // Todo: 從設定檔讀取
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { gclient: grpc_client.clone() }))
            .wrap(middleware::NormalizePath::trim())
            .wrap(Logger::default())
            .configure(configure_app)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await?;
    Ok(())
}
