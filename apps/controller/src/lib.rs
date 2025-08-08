mod communication;
mod config;
mod globals;
mod runner;
use chm_project_const::ProjectConst;
pub use config::{config, ID, NEED_EXAMPLE};
pub use globals::{reload_globals, GlobalConfig};
use runner::{one::first_run, two::run};

pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn entry() -> ConResult<()> {
    tracing::debug!("Controller 啟動中...");
    tracing::debug!("初始化全域設定...");
    config().await?;
    tracing::debug!("全域設定已初始化");
    tracing::debug!("檢查資料目錄...");
    let data_dir = ProjectConst::data_path();
    std::fs::create_dir_all(&data_dir)?;
    tracing::debug!("資料目錄已檢查");
    tracing::debug!("檢查是否為第一次執行...");
    let marker_path = data_dir.join(".controller_first_run.done");
    let is_first_run = !marker_path.exists();
    if is_first_run {
        first_run(&marker_path).await?;
        tracing::debug!("第一次執行檢查完成");
    }
    tracing::debug!("開始執行二階段 Controller...");
    run().await?;
    tracing::debug!("二階段Controller 執行完成");
    Ok(())
}
