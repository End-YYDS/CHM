#![allow(non_camel_case_types)]
use crate::{
    commons::{ResponseResult, ResponseType},
    handles::handles_scope,
};
pub use crate::{config::config, globals::GlobalConfig};
use actix_session::Session;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::{self, from_fn, Next},
    web::{scope, ServiceConfig},
    Error, FromRequest, HttpResponse,
};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_grpc::{restful::restful_service_client::RestfulServiceClient, tonic::transport::Channel};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
mod auth;
pub mod commons;
mod handles;
pub mod json_schemas;
pub use config::CertInfo;
pub use json_schemas::AllSchemas;
pub mod openapi;
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
    pub security:   ApiSecurityConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApiSecurityConfig {
    pub frontend_origin: String,
    pub cookie_name:     String,
    pub session_key:     String,
    pub same_site:       String,
    pub cookie_secure:   bool,
}
impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            frontend_origin: String::from("https://localhost:3000"),
            cookie_name:     String::from("chm_sid"),
            session_key:     chm_password::generate_key64_base64(),
            same_site:       String::from("Lax"),
            cookie_secure:   true,
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

fn is_public(req: &ServiceRequest) -> bool {
    let path = req.path();
    let m = req.method().as_str();
    if m == "OPTIONS" {
        return true;
    }
    matches!((m, path), ("POST", "/api/login"))
}

async fn auth_md(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if is_public(&req) {
        let res = next.call(req).await?;
        return Ok(res.map_into_left_body());
    }

    let session = match Session::extract(req.request()).await {
        Ok(s) => s,
        Err(_) => {
            let (r, _) = req.into_parts();
            let resp = HttpResponse::Unauthorized().json(ResponseResult {
                r#type:  ResponseType::Err,
                message: "Session 取得失敗，請重新登入".to_string(),
            });
            let sr = ServiceResponse::new(r, resp.map_into_right_body());
            return Ok(sr);
        }
    };

    let logged_in = matches!(session.get::<String>("uid"), Ok(Some(_)))
        || matches!(session.get::<i64>("uid"), Ok(Some(_)));

    if !logged_in {
        let (r, _) = req.into_parts();
        let resp = HttpResponse::Unauthorized().json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "驗證失敗，請重新登入".to_string(),
        });
        let sr = ServiceResponse::new(r, resp.map_into_right_body());
        return Ok(sr);
    }

    let res = next.call(req).await?;
    Ok(res.map_into_left_body())
}

pub fn configure_app(cfg: &mut ServiceConfig) {
    let auth_gate = from_fn(auth_md);
    cfg.service(
        scope("/api")
            .wrap(middleware::NormalizePath::trim())
            .wrap(auth_gate)
            .configure(handles_scope),
    );
}
