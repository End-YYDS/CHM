use chm_project_const::uuid::Uuid;
use serde::{Deserialize, Serialize};
pub use serde_json::Value;
use std::{net::SocketAddrV4, path::Path};

pub type CHMResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceKind {
    Controller,
    Mca,
    Dns,
    Ldap,
    Dhcp,
    Api,
    Agent,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDescriptor {
    pub kind:        ServiceKind,
    pub uri:         String,
    #[serde(default, deserialize_with = "crate::none_if_string_none")]
    pub health_name: Option<String>,
    pub is_server:   bool,
    // #[serde(default, deserialize_with = "crate::none_if_string_none")]
    // pub inner_domain_name: Option<String>,
    pub hostname:    String,
    pub uuid:        Uuid,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InitData {
    Bootstrap { root_ca_pem: Vec<u8> },
    Finalize { id: Uuid, cert_pem: Vec<u8>, chain_pem: Vec<Vec<u8>> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapResp {
    pub csr_pem:      Vec<u8>,
    pub socket:       SocketAddrV4,
    pub service_desp: ServiceDescriptor,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitEnvelope<T> {
    pub code: String,
    #[serde(flatten)]
    pub data: T,
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
pub async fn atomic_write(path: &Path, content: &[u8]) -> CHMResult<()> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content).await?;
    fs::rename(&tmp_path, path).await?;
    Ok(())
}
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "grpc-client")]
pub mod gclient;
#[cfg(feature = "grpc-client")]
pub use backoff::ExponentialBackoff;
use tokio::fs;

#[cfg(feature = "grpc-server")]
pub mod gserver;
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
