use config::get_config_manager;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmg = get_config_manager(None);
    dbg!(cmg);
    Ok(())
}
