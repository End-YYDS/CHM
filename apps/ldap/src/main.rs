use argh::FromArgs;
use chm_grpc::{ldap::ldap_service_server::LdapServiceServer, tonic::transport::Server};
use ldap::{config, service::MyLdapService, GlobalConfig, ID, NEED_EXAMPLE};
use std::{net::SocketAddr, sync::atomic::Ordering::Relaxed};
use tracing_subscriber::EnvFilter;
#[derive(FromArgs, Debug, Clone)]
/// Ldap 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}
// TODO: 添加叢集交換的FN

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(debug_assertions)]
    let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args: Args = argh::from_env();
    if args.init_config {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    tracing::info!("配置檔案加載完成");
    let (address, port, ldap_url, bind_dn, bind_password) = GlobalConfig::with(|cfg| {
        let address = cfg.server.host.clone();
        let port = cfg.server.port;
        let ldap_url = cfg.extend.ldap_settings.url.clone();
        let bind_dn = cfg.extend.ldap_settings.bind_dn.clone();
        let bind_password = cfg.extend.ldap_settings.bind_password.clone();
        (address, port, ldap_url, bind_dn, bind_password)
    });
    let addr = SocketAddr::new(address.parse()?, port);
    let server = MyLdapService::new(ldap_url, bind_dn, bind_password);
    // TODO: 啟用TLS
    // TODO: 啟用叢集
    // TODO: 添加Controller檢查

    println!("gRPC server running on {addr}");
    Server::builder().add_service(LdapServiceServer::new(server)).serve(addr).await?;

    Ok(())
}
