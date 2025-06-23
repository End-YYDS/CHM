use ca::{
    cert::{process::CertificateProcess, store::StoreFactory},
    config::{config, NEED_EXAMPLE},
    globals::GlobalConfig,
    *,
};
use std::sync::atomic::Ordering::Relaxed;
use std::{env, fs, net::SocketAddr, path::Path, sync::Arc};
#[actix_web::main]
async fn main() -> CaResult<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        config().await?;
        return Ok(());
    }
    config().await?;
    if GlobalConfig::has_active_readers() {
        eprintln!("還有讀鎖沒釋放!-0");
    }
    let cfg = GlobalConfig::read().await;
    let cmg = &cfg.settings;
    let project_dir = &cfg.dirs;

    let marker_path = Path::new(project_dir.data_dir()).join("first_run.done");
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let first_run = !marker_path.exists();
    let ca_passwd = &cmg.certificate.passphrase;
    let store = StoreFactory::create_store().await?;
    let addr = SocketAddr::new(cmg.server.host.parse()?, cmg.server.port);
    let cert_handler = Arc::new(CertificateProcess::load(
        &cmg.certificate.rootca,
        &cmg.certificate.rootca_key,
        ca_passwd,
        store,
    )?);
    drop(cfg);
    if args.iter().any(|a| a == "--debug") {
        // dbg!(&cfg);
        // one_cert(&cert_handler).await?;
        println!("Debug mode enabled");
        create_new_rootca().await?;
        return Ok(());
    }
    if first_run {
        let mut mini_c = mini_controller_cert(&cert_handler).await?;
        ca_grpc_cert(&cert_handler).await?;
        grpc_test_cert(&cert_handler).await?;
        mini_c.start(addr, marker_path.clone()).await?;
    }
    if marker_path.exists() {
        start_grpc(addr, cert_handler.clone()).await?;
    }
    Ok(())
}
