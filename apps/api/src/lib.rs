#![allow(non_camel_case_types)]
#![allow(dead_code)]
use crate::handles::handles_scope;
use actix_web::web::{scope, ServiceConfig};
use chm_config_bus::declare_config_bus;
pub use config::{config, ID, NEED_EXAMPLE};
pub use globals::GlobalConfig;
use serde::Deserialize;
mod commons;
mod config;
mod handles;

pub type ApiResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
declare_config_bus! {
    pub mod globals {
        type Settings = crate::config::Settings;
        const ID: &str = crate::ID;
        save = chm_config_loader::store_config;
        load = chm_config_loader::load_config;
    }
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
