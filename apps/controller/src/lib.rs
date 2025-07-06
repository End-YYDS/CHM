mod communication;
mod globals;
mod runner;
use chm_project_const::ProjectConst;
pub use globals::{globals_lock, reload_globals};
use runner::{one::first_run, two::run};

pub type ConResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn entry() -> ConResult<()> {
    let data_dir = ProjectConst::data_path();
    std::fs::create_dir_all(&data_dir)?;
    let marker_path = data_dir.join(".controller_first_run.done");
    let is_first_run = !marker_path.exists();
    if is_first_run {
        first_run(&marker_path).await?;
    }
    run().await?;
    Ok(())
}
