use controller::{ConResult, ID, NEED_EXAMPLE};
use std::sync::atomic::Ordering::Relaxed;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ConResult<()> {
    let filter = if cfg!(debug_assertions) {
        EnvFilter::from_default_env().add_directive("info".parse().unwrap())
    } else {
        EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args: Vec<String> = std::env::args().collect();
    tracing::debug!("啟動 Controller，參數: {:?}", args);
    // TODO: 添加Argh解析CLI參數
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        controller::config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    tracing::info!("正在啟動Controller...");
    controller::entry().await?;
    Ok(())
}
