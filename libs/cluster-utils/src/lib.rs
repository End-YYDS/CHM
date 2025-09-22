use serde::{Deserialize, Serialize};
pub use serde_json::Value;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T = Value> {
    pub message: String,
    pub ok:      bool,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data:    Option<T>,
}
impl<T> ApiResponse<T> {
    #[inline]
    pub fn ok_msg(message: impl Into<String>) -> Self {
        Self { message: message.into(), ok: true, data: None }
    }
    #[inline]
    pub fn ok_with(message: impl Into<String>, data: T) -> Self {
        Self { message: message.into(), ok: true, data: Some(data) }
    }
    #[inline]
    pub fn err(message: impl Into<String>) -> Self {
        Self { message: message.into(), ok: false, data: None }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitEnvelope<T> {
    pub code: String,
    #[serde(flatten)]
    pub data: T,
}
#[cfg(feature = "client")]
mod client;
mod macros;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "client")]
pub use client::ClientCluster as Default_ClientCluster;

#[cfg(feature = "server")]
pub use server::ServerCluster as Default_ServerCluster;

#[cfg(feature = "server")]
pub mod _reexports {
    pub use actix_web::{
        web::{post, resource, Data, Json, ServiceConfig},
        HttpRequest, HttpResponse, Responder,
    };
    pub use tokio::{
        fs,
        sync::{mpsc::Sender, RwLock},
    };
}
