use controller::ConResult;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ConResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    tracing::info!("正在啟動Controller...");
    controller::entry().await?;
    Ok(())
}
