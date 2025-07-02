mod first;
mod run;
use first::first_run;
use project_const::ProjectConst;
use run::run;

pub type ConResult<T> = Result<T, Box<dyn std::error::Error>>;

pub async fn entry() -> ConResult<()> {
    let data_dir = ProjectConst::data_path();
    std::fs::create_dir_all(&data_dir)?;
    let marker_path = data_dir.join(".controller_first_run.done");
    let is_first_run = !marker_path.exists();
    if is_first_run {
        first_run().await?;
    }
    run().await?;
    Ok(())
}
