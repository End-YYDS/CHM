#![allow(clippy::crate_in_macro_def)]
#[doc(hidden)]
pub mod _reexports {
    pub use arc_swap::ArcSwap;
    pub use chm_config_loader::{load_config, store_config};
    pub use chm_dns_resolver::DnsResolver;
    pub use chm_project_const::{uuid::Uuid, ProjectConst};
    pub use humantime_serde;
    pub use serde::{Deserialize, Serialize};
    pub use std::sync::{atomic::Ordering::Relaxed, Arc, OnceLock};
    pub use tokio::sync::watch;
}

#[macro_export]
macro_rules! declare_config {
    () => {
        pub(crate) mod config {
            use std::{
                net::{IpAddr, Ipv4Addr},
                path::PathBuf,time::Duration,
            };
            use $crate::_reexports::{
                load_config, store_config, Deserialize, DnsResolver, ProjectConst, Relaxed, Serialize,
                Uuid,humantime_serde,
            };
            pub type ConfigResult<T> =
                core::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

            #[derive(Debug, Serialize, Deserialize, Clone)]
            pub struct Server {
                #[serde(default = "Server::default_hostname")]
                pub hostname:  String,
                #[serde(default = "Server::default_host")]
                pub host:      String,
                #[serde(default = "Server::default_port")]
                pub port:      u16,
                #[serde(default = "Server::default_otp_len")]
                pub otp_len:   usize,
                #[serde(with = "humantime_serde", default = "Server::default_opt_time")]
                pub otp_time: Duration,
                #[serde(default = "Server::default_unique_id")]
                pub unique_id: Uuid,
                #[serde(default = "Server::default_dns_server")]
                pub dns_server: String,
            }
            impl Server {
                fn default_hostname() -> String { crate::ID.into() }
                fn default_host() -> String {
                    #[cfg(debug_assertions)]
                    {
                        IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        DnsResolver::get_local_ip()
                            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                            .to_string()
                    }
                }
                fn default_port() -> u16 {
                    #[cfg(debug_assertions)]
                    crate::DEFAULT_PORT
                    #[cfg(not(debug_assertions))]
                    ProjectConst::SOFTWARE_PORT
                }
                fn default_otp_len() -> usize { crate::DEFAULT_OTP_LEN }
                fn default_opt_time() -> Duration {
                    Duration::from_secs(30)
                }
                fn default_unique_id() -> Uuid { Uuid::new_v4() }
                fn default_dns_server() -> String {
                    let mut dns_server = String::from("http://");
                    #[cfg(debug_assertions)]
                    {
                        let s = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
                        dns_server.push_str(&s);
                        dns_server.push_str(":50053");
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let s = chm_dns_resolver::DnsResolver::get_local_ip()
                            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                            .to_string();
                        dns_server.push_str(&s);
                    }
                    dns_server
                }
            }
            impl Default for Server {
                fn default() -> Self {
                    Self {
                        hostname:  Self::default_hostname(),
                        host:      Self::default_host(),
                        port:      Self::default_port(),
                        otp_len:   Self::default_otp_len(),
                        otp_time:  Self::default_opt_time(),
                        unique_id: Self::default_unique_id(),
                        dns_server: Self::default_dns_server(),
                    }
                }
            }

            #[derive(Debug, Deserialize, Serialize, Clone)]
            pub struct Certificate {
                #[serde(default = "Certificate::default_rootca")]
                pub root_ca:     PathBuf,
                #[serde(default = "Certificate::default_client_cert")]
                pub client_cert: PathBuf,
                #[serde(default = "Certificate::default_client_key")]
                pub client_key:  PathBuf,
                #[serde(default = "Certificate::default_passphrase")]
                pub passphrase:  String,
                #[serde(default, rename = "CertInfo")]
                pub cert_info:   CertInfo,
            }

            #[derive(Debug, Serialize, Deserialize, Clone)]
            pub struct CertInfo {
                pub bits:     u32,
                pub country:  String,
                pub state:    String,
                pub locality: String,
                pub org:      String,
                pub cn:       String,
                pub san:      Vec<String>,
                pub days:     u32,
            }
            impl Default for CertInfo {
                fn default() -> Self {
                    Self {
                        bits: 4096,
                        country: "TW".into(),
                        state: "Taiwan".into(),
                        locality: "Taipei".into(),
                        org: "CHM-INIT".into(),
                        cn: crate::ID.into(),
                        san: vec!["127.0.0.1".into(), "localhost".into(),format!("{}.chm.com", crate::ID)],
                        days: 1,
                    }
                }
            }
            impl Certificate {
                fn default_rootca() -> PathBuf { ProjectConst::certs_path().join("rootCA.pem") }
                fn default_client_cert() -> PathBuf { ProjectConst::certs_path().join(format!("{}.pem", crate::ID)) }
                fn default_client_key() -> PathBuf { ProjectConst::certs_path().join(format!("{}.key", crate::ID)) }
                fn default_passphrase() -> String { "".to_string() }
            }
            impl Default for Certificate {
                fn default() -> Self {
                    Certificate {
                        root_ca:     Self::default_rootca(),
                        client_cert: Self::default_client_cert(),
                        client_key:  Self::default_client_key(),
                        passphrase:  Self::default_passphrase(),
                        cert_info:   CertInfo::default(),
                    }
                }
            }

            #[derive(Debug, Default, Serialize, Deserialize, Clone)]
            #[serde(rename_all = "PascalCase")]
            pub struct Settings {
                #[serde(default)]
                pub server:      Server,
                #[serde(default)]
                pub certificate: Certificate,
            }

            impl Settings {
                pub fn new() -> ConfigResult<Self> {
                    Ok(load_config(crate::ID, None, None)?)
                }
                pub async fn init(path: &str) -> ConfigResult<()> {
                    store_config(&Settings::default(), path).await?;
                    println!("Generated default config at {path}");
                    Ok(())
                }
            }

            pub async fn config() -> ConfigResult<()> {
                if crate::NEED_EXAMPLE.load(Relaxed) {
                    Settings::init(&format!("{}_config.toml.example", crate::ID)).await?;
                    return Ok(());
                }
                let settings = Settings::new()?;
                crate::globals::GlobalConfig::init(settings);
                Ok(())
            }
        }
    };
    (
        extend = $extend_ty:ty
        $(, default_extend = $extend_default:expr; )?
    ) => {
        pub(crate) mod config {
            use std::{
                net::{IpAddr, Ipv4Addr},
                path::PathBuf,time::Duration,
            };
            use $crate::_reexports::{
                load_config, store_config, Deserialize, DnsResolver, Serialize,
                ProjectConst, Uuid, Relaxed,humantime_serde,
            };
            pub type ConfigResult<T> = core::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
            #[derive(Debug, Serialize, Deserialize, Clone)]
            pub struct Server {
                #[serde(default = "Server::default_hostname")]
                pub hostname:  String,
                #[serde(default = "Server::default_host")]
                pub host:      String,
                #[serde(default = "Server::default_port")]
                pub port:      u16,
                #[serde(default = "Server::default_otp_len")]
                pub otp_len:   usize,
                #[serde(with = "humantime_serde", default = "Server::default_opt_time")]
                pub otp_time: Duration,
                #[serde(default = "Server::default_unique_id")]
                pub unique_id: Uuid,
                #[serde(default = "Server::default_dns_server")]
                pub dns_server: String,
            }
            impl Server {
                fn default_hostname() -> String {
                    crate::ID.into()
                }
                fn default_host() -> String {
                    #[cfg(debug_assertions)]
                    {
                        IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        DnsResolver::get_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)).to_string()
                    }
                }
                fn default_port() -> u16 {
                    #[cfg(debug_assertions)]
                    {
                        crate::DEFAULT_PORT
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        ProjectConst::SOFTWARE_PORT
                    }
                }
                fn default_otp_len() -> usize {
                    crate::DEFAULT_OTP_LEN
                }
                fn default_opt_time() -> Duration {
                    Duration::from_secs(30)
                }
                fn default_unique_id() -> Uuid {
                    Uuid::new_v4()
                }
                fn default_dns_server() -> String {
                    let mut dns_server = String::from("http://");
                    #[cfg(debug_assertions)]
                    {
                        let s = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
                        dns_server.push_str(&s);
                        dns_server.push_str(":50053");
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        let s = chm_dns_resolver::DnsResolver::get_local_ip()
                            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
                            .to_string();
                        dns_server.push_str(&s);
                    }
                    dns_server
                }
            }
            impl Default for Server {
                fn default() -> Self {
                    Self {
                        hostname:  Self::default_hostname(),
                        host:      Self::default_host(),
                        port:      Self::default_port(),
                        otp_len:   Self::default_otp_len(),
                        otp_time:  Self::default_opt_time(),
                        unique_id: Self::default_unique_id(),
                        dns_server: Self::default_dns_server(),
                    }
                }
            }
            #[derive(Debug, Deserialize, Serialize, Clone)]
            pub struct Certificate {
                #[serde(default = "Certificate::default_rootca")]
                /// 根憑證
                pub root_ca:     PathBuf,
                #[serde(default = "Certificate::default_client_cert")]
                /// 客戶端憑證
                pub client_cert: PathBuf,
                #[serde(default = "Certificate::default_client_key")]
                /// 客戶端私鑰
                pub client_key:  PathBuf,
                #[serde(default = "Certificate::default_passphrase")]
                /// 根憑證的密碼短語
                pub passphrase:  String,
                #[serde(default, rename = "CertInfo")]
                pub cert_info:   CertInfo,
            }

            #[derive(Debug, Serialize, Deserialize, Clone)]
            pub struct CertInfo {
                pub bits:     u32,
                pub country:  String,
                pub state:    String,
                pub locality: String,
                pub org:      String,
                pub cn:       String,
                pub san:      Vec<String>,
                pub days:     u32,
            }

            impl Default for CertInfo {
                fn default() -> Self {
                    Self {
                        bits:     4096,
                        country:  "TW".into(),
                        state:    "Taiwan".into(),
                        locality: "Taipei".into(),
                        org:      "CHM-INIT".into(),
                        cn:       crate::ID.into(),
                        san:      vec!["127.0.0.1".into(), "localhost".into(),format!("{}.chm.com", crate::ID)],
                        days:     1,
                    }
                }
            }

            impl Certificate {
                fn default_rootca() -> PathBuf {
                    ProjectConst::certs_path().join("rootCA.pem")
                }
                fn default_client_cert() -> PathBuf {
                    ProjectConst::certs_path().join(format!("{}.pem", crate::ID))
                }
                fn default_client_key() -> PathBuf {
                    ProjectConst::certs_path().join(format!("{}.key", crate::ID))
                }
                fn default_passphrase() -> String {
                    "".to_string()
                }
            }

            impl Default for Certificate {
                fn default() -> Self {
                    Certificate {
                        root_ca:     Certificate::default_rootca(),
                        client_cert: Certificate::default_client_cert(),
                        client_key:  Certificate::default_client_key(),
                        passphrase:  Certificate::default_passphrase(),
                        cert_info:   CertInfo::default(),
                    }
                }
            }

            #[doc(hidden)]
            pub(crate) fn __extend_default() -> $extend_ty {
                $crate::declare_config!(@__extend_default_impl $extend_ty $(, $extend_default)?)
            }

            #[derive(Debug, Default, Serialize, Deserialize, Clone)]
            #[serde(rename_all = "PascalCase")]
            pub struct Settings {
                #[serde(default)]
                pub server:      Server,
                #[serde(default)]
                /// 憑證設定
                pub certificate: Certificate,
                #[serde(default = "__extend_default")]
                pub extend:      $extend_ty,
            }

            impl Settings {
                pub fn new() -> ConfigResult<Self> {
                    Ok(load_config(crate::ID, None, None)?)
                }
                pub async fn init(path: &str) -> ConfigResult<()> {
                    store_config(&Settings::default(), path).await?;
                    println!("Generated default config at {path}");
                    Ok(())
                }
            }
            pub async fn config() -> ConfigResult<()> {
                if crate::NEED_EXAMPLE.load(Relaxed) {
                    Settings::init(format!("{}_config.toml.example", crate::ID).as_str()).await?;
                    return Ok(());
                }
                let settings = Settings::new()?;
                crate::globals::GlobalConfig::init(settings);
                Ok(())
            }
        }
    };
    (@__extend_default_impl $t:ty) => {
        <$t as Default>::default()
    };
    (@__extend_default_impl $t:ty, $expr:expr) => {{
        let v: $t = $expr;
        v
    }};
}

#[macro_export]
macro_rules! declare_config_bus {
    () => {
        pub(crate) mod globals {
            use $crate::_reexports::{load_config, store_config, watch, Arc, ArcSwap, OnceLock};
            #[derive(Debug)]
            pub struct GlobalConfig;
            static GLOBALS: OnceLock<ArcSwap<crate::config::Settings>> = OnceLock::new();
            static RELOAD_TX: OnceLock<watch::Sender<Arc<crate::config::Settings>>> =
                OnceLock::new();
            pub type Result<T> =
                core::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

            impl GlobalConfig {
                pub fn init(settings: crate::config::Settings) {
                    GLOBALS
                        .set(ArcSwap::from_pointee(settings))
                        .expect("Global configuration already initialized");
                    let _ = RELOAD_TX.set(watch::channel(Self::get()).0);
                }
                #[inline]
                pub fn get() -> Arc<crate::config::Settings> {
                    GLOBALS.get().expect("Global configuration not initialized").load_full()
                }

                #[inline]
                pub fn with<R>(f: impl FnOnce(&crate::config::Settings) -> R) -> R {
                    let arc = Self::get();
                    f(arc.as_ref())
                }
                pub fn update_with<F>(f: F)
                where
                    F: Fn(&mut crate::config::Settings) + Clone,
                {
                    GLOBALS.get().expect("Global configuration not initialized").rcu(|cur| {
                        let mut next = (**cur).clone();
                        f(&mut next);
                        Arc::new(next)
                    });
                }
                pub fn send_reload() {
                    if let Some(tx) = RELOAD_TX.get() {
                        let _ = tx.send(Self::get());
                    }
                }
                pub fn replace_all(new_settings: crate::config::Settings) {
                    GLOBALS
                        .get()
                        .expect("Global configuration not initialized")
                        .store(Arc::new(new_settings));
                    Self::send_reload();
                }
                pub fn subscribe_reload() -> watch::Receiver<Arc<crate::config::Settings>> {
                    RELOAD_TX.get().expect("reload bus not initialized").subscribe()
                }
                pub async fn save_config() -> Result<()> {
                    let cfg = Self::get();
                    let config_name = format!("{}_config.toml", crate::ID);
                    store_config(&*cfg, &config_name).await?;
                    Ok(())
                }
                pub async fn reload_config() -> Result<()> {
                    let new_cfg = load_config(crate::ID, None, None)?;
                    Self::replace_all(new_cfg);
                    Ok(())
                }
            }
        }
    };
}
