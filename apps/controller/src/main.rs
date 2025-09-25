use controller::{config, Args, ConResult, ID, NEED_EXAMPLE};
use std::sync::atomic::Ordering::Relaxed;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ConResult<()> {
    #[cfg(debug_assertions)]
    let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args: Args = argh::from_env();
    tracing::debug!("啟動 Controller，參數: {:?}", args);
    if args.init_config {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        controller::config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    tracing::info!("Controller 啟動中...");
    tracing::debug!("初始化全域設定...");
    config().await?;
    tracing::debug!("全域設定已初始化");
    tracing::info!("正在啟動Controller...");
    controller::entry(args).await?;
    Ok(())
}
