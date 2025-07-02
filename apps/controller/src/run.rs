use crate::ConResult;

pub async fn run() -> ConResult<()> {
    tracing::info!("Controller 正在運行...");
    Ok(())
}
