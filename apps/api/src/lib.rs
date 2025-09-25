#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::handles::handles_scope;
pub use crate::{config::config, globals::GlobalConfig};
use actix_web::web::{scope, ServiceConfig};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_grpc::{restful::restful_service_client::RestfulServiceClient, tonic::transport::Channel};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
mod commons;
// mod config;
mod handles;
pub use config::CertInfo;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHM_API";
pub(crate) const DEFAULT_PORT: u16 = 50050;
pub(crate) const DEFAULT_OTP_LEN: usize = 6;
pub type ApiResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Services {
    #[serde(default = "Services::default_controller")]
    pub controller: String,
}
impl Services {
    fn default_controller() -> String {
        let mut cip = String::from("https://");
        #[cfg(debug_assertions)]
        {
            let c = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).to_string();
            cip.push_str(&c);
            cip.push_str(":50051");
        }
        #[cfg(not(debug_assertions))]
        {
            let c = chm_dns_resolver::DnsResolver::get_local_ip()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                .to_string();
            cip.push_str(&c);
        }
        cip
    }
}
impl Default for Services {
    fn default() -> Self {
        Self { controller: Self::default_controller() }
    }
}

declare_config!(extend = crate::Services);
declare_config_bus!();

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AppState {
    pub gclient: RestfulServiceClient<Channel>,
}

pub fn configure_app(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api").configure(handles_scope));
}

pub fn none_if_string_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt.as_deref() {
        Some("None") => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        _ => Ok(opt),
    }
}
