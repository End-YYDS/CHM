use chm_dns_resolver::DnsResolver;
use chm_project_const::ProjectConst;
use tokio::sync::{OnceCell, RwLock};
#[derive(Debug)]
pub struct GlobalsVar {
    pub root_ca_cert: Option<Vec<u8>>,
    pub client_cert:  Option<Vec<u8>>,
    pub client_key:   Option<Vec<u8>>,
    pub mca_info:     Option<String>,
    pub mdns_info:    Option<String>,
    pub dns_resolver: DnsResolver,
}

static GLOBALS: OnceCell<RwLock<GlobalsVar>> = OnceCell::const_new();

pub const DEFAULT_CA: &str = "https://mCA.chm.com:50052";
pub const DEFAULT_DNS: &str = "http://127.0.0.1:50053";

pub async fn certificate_loader(
) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, DnsResolver, String) {
    let cert_path = ProjectConst::certs_path();
    let root_ca_cert = std::fs::read(cert_path.join("rootCA.pem")).ok();
    let client_cert = std::fs::read(cert_path.join("controller.pem")).ok();
    let client_key = std::fs::read(cert_path.join("controller.key")).ok();
    let mut resolver = DnsResolver::new(DEFAULT_DNS).await;
    let mca_ip = resolver.resolve_ip(DEFAULT_CA).await.expect("解析 DEFAULT_CA 失敗");
    (root_ca_cert, client_cert, client_key, resolver, mca_ip)
}

impl GlobalsVar {
    pub async fn load() -> Self {
        let (root_ca_cert, client_cert, client_key, resolver, mca_ip) = certificate_loader().await;
        GlobalsVar {
            root_ca_cert,
            client_cert,
            client_key,
            mca_info: Some(mca_ip),
            mdns_info: Some(DEFAULT_DNS.to_string()),
            dns_resolver: resolver,
        }
    }
}
pub async fn globals_lock() -> &'static RwLock<GlobalsVar> {
    GLOBALS
        .get_or_init(|| async {
            let initial = GlobalsVar::load().await;
            RwLock::new(initial)
        })
        .await
}
pub async fn reload_globals() {
    let lock = globals_lock().await;
    let mut w = lock.write().await;
    let (root_ca_cert, client_cert, client_key, resolver, mca_ip) = certificate_loader().await;
    w.root_ca_cert = root_ca_cert;
    w.client_cert = client_cert;
    w.client_key = client_key;
    w.dns_resolver = resolver;
    w.mca_info = Some(mca_ip);
    w.mdns_info = Some(DEFAULT_DNS.to_string());
    tracing::info!("GlobalsVar DNS 重新載入完成");
}
