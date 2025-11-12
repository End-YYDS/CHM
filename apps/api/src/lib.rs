#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::handles::handles_scope;
pub use crate::{config::config, globals::GlobalConfig};
use actix_web::web::{scope, ServiceConfig};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_grpc::{restful::restful_service_client::RestfulServiceClient, tonic::transport::Channel};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
mod auth;
pub mod commons;
mod handles;
pub use config::CertInfo;
pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHM_API";
pub(crate) const DEFAULT_PORT: u16 = 50050;
pub(crate) const DEFAULT_OTP_LEN: usize = 6;
pub type ApiResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type RestfulResult<T> = actix_web::Result<T, commons::translate::AppError>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApiConfigExtend {
    #[serde(default = "ApiConfigExtend::default_controller")]
    pub controller: String,
    #[serde(default)]
    pub security: ApiSecurityConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApiSecurityConfig {
    pub frontend_origin: String,
    pub cookie_name: String,
    pub session_key: String,
    pub same_site: String,
    pub cookie_secure: bool,
}
impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            frontend_origin: String::from("https://localhost:3000"),
            cookie_name: String::from("chm_sid"),
            session_key: chm_password::generate_key64_base64(),
            same_site: String::from("Lax"),
            cookie_secure: true,
        }
    }
}
impl ApiConfigExtend {
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
impl Default for ApiConfigExtend {
    fn default() -> Self {
        Self { controller: Self::default_controller(), security: ApiSecurityConfig::default() }
    }
}

declare_config!(extend = crate::ApiConfigExtend);
declare_config_bus!();

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AppState {
    pub gclient: RestfulServiceClient<Channel>,
}

pub fn configure_app(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api").configure(handles_scope));
}
