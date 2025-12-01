use argh::FromArgs;
use chm_cluster_utils::software_init;
use controller::{config, Args, ConResult, ID, NEED_EXAMPLE};
use std::sync::atomic::Ordering::Relaxed;

#[tokio::main]
async fn main() -> ConResult<()> {
    let args = software_init!(Args);
    if args.cmd.is_none() {
        let app_name = std::env::args().next().unwrap_or_else(|| "controller".to_string());
        let msg = Args::from_args(&[app_name.as_str()], &["help"]).unwrap_err().output;
        eprintln!("{msg}");
        return Ok(());
    }
    controller::entry(args).await?;
    Ok(())
}
