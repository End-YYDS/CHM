use actix_web::{middleware, middleware::Logger, HttpServer};
use api_server::configure_app;
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    HttpServer::new(|| {
        actix_web::App::new()
            .wrap(middleware::NormalizePath::trim())
            .wrap(Logger::default())
            .configure(configure_app)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await?;
    Ok(())
}
