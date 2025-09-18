use ca::{
    cert::{
        process::CertificateProcess,
        store::{CertificateStore, StoreFactory},
    },
    config::{config, NEED_EXAMPLE},
    globals::GlobalConfig,
    *,
};
use chm_project_const::ProjectConst;
use std::{
    env, fs,
    net::SocketAddr,
    ops::ControlFlow,
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tracing_subscriber::EnvFilter;
#[actix_web::main]
async fn main() -> CaResult<()> {
    let filter = if cfg!(debug_assertions) {
        EnvFilter::from_default_env().add_directive("info".parse().unwrap())
    } else {
        EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args: Vec<String> = env::args().collect();
    tracing::debug!("啟動 mCA 伺服器，參數: {:?}", args);
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 CA_config.toml.example");
        return Ok(());
    }
    if args.iter().any(|a| a == "--create-ca") {
        tracing::info!("創建新的 RootCA...");
        create_new_rootca().await?; //[ ]: 安裝程式需要先行調用此，產生RootCA
        let certs = ProjectConst::certs_path();
        tracing::info!("RootCA 已創建，請檢查 {}/rootCA.pem", certs.display());
        return Ok(());
    }
    tracing::info!("正在載入配置...");
    config().await?;
    tracing::info!("配置載入完成，開始啟動 mCA...");
    tracing::trace!("進入GlobalConfig讀取鎖定區域");
    let cmg = GlobalConfig::get();
    let unique_id = cmg.server.unique_id.clone().parse().unwrap_or_else(|_| {
        tracing::error!("無效的 unique_id，使用預設值");
        uuid::Uuid::new_v4()
    });
    let marker_path = ProjectConst::data_path().join(".ca_first_run.done");
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let first_run = !marker_path.exists();
    let store = StoreFactory::create_store().await?;
    let store: Arc<dyn CertificateStore> = Arc::from(store);
    let addr = SocketAddr::new(cmg.server.host.parse()?, cmg.server.port);
    tracing::trace!("讀取配置完成，開始載入憑證處理器...");
    let cert_handler = Arc::new(
        CertificateProcess::load(
            &cmg.certificate.rootca,
            &cmg.certificate.rootca_key,
            &cmg.certificate.passphrase,
            cmg.certificate.crl_update_interval,
            store,
        )
        .await?,
    );
    tracing::trace!("憑證處理器載入完成，開始啟動 mCA 伺服器...");
    tracing::trace!("GlobalConfig讀取鎖定區域已釋放");
    tracing::info!("mCA 伺服器將在 {addr} 上運行");
    tracing::debug!("mCA 伺服器的唯一識別碼: {}", unique_id);

    if first_run {
        tracing::info!("第一次啟動，正在初始化 MiniController...");
        let mut mini_c = mini_controller_cert(&cert_handler, unique_id).await?;
        tracing::info!("MiniController 初始化完成，開始創建憑證...");
        tracing::debug!("創建 ca_grpc 憑證...");
        ca_grpc_cert(&cert_handler, unique_id).await?;
        if cfg!(debug_assertions) {
            tracing::debug!("創建 grpc_test 憑證...");
            grpc_test_cert(&cert_handler).await?;
            tracing::debug!("創建 one_test 憑證...");
            one_cert(&cert_handler).await?;
            tracing::debug!("憑證創建完成");
            tracing::info!("正在啟動 MiniController...");
        }
        if let ControlFlow::Break(e) = mini_c.start(addr, marker_path.clone(), unique_id).await {
            tracing::error!("MiniController 初始化失敗: {}", e);
            return Ok(());
        }
        tracing::debug!("工作轉交完成，即將刪除MiniController Certificate");
        let cert_path = ProjectConst::certs_path().join("mini_controller.pem");
        let key_path = ProjectConst::certs_path().join("mini_controller.key");
        tokio::fs::remove_file(cert_path).await?;
        tokio::fs::remove_file(key_path).await?;
    }
    if marker_path.exists() {
        tracing::info!("mCA 伺服器已經初始化過，開始啟動 gRPC 服務...");
        start_grpc(addr, cert_handler.clone()).await?;
    }
    Ok(())
}
