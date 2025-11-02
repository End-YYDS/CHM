use chm_project_const::uuid::Uuid;
use serde::{Deserialize, Serialize};
pub use serde_json::Value;
use std::{
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    net::SocketAddrV4,
    path::Path,
    str::FromStr,
};

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
impl Display for ServiceKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ServiceKind::Controller => "Controller",
            ServiceKind::Mca => "Mca",
            ServiceKind::Dns => "Dns",
            ServiceKind::Ldap => "Ldap",
            ServiceKind::Dhcp => "Dhcp",
            ServiceKind::Api => "Api",
            ServiceKind::Agent => "Agent",
        };
        write!(f, "{s}")
    }
}
impl FromStr for ServiceKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "controller" => Ok(ServiceKind::Controller),
            "mca" => Ok(ServiceKind::Mca),
            "dns" => Ok(ServiceKind::Dns),
            "ldap" => Ok(ServiceKind::Ldap),
            "dhcp" => Ok(ServiceKind::Dhcp),
            "api" => Ok(ServiceKind::Api),
            "agent" => Ok(ServiceKind::Agent),
            _ => Err(format!("Unknown service kind: {s}")),
        }
    }
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
impl PartialEq for ServiceDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}
impl Eq for ServiceDescriptor {}

impl Hash for ServiceDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uuid.hash(state);
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InitData {
    Bootstrap {
        root_ca_pem: Vec<u8>,
        con_uuid:    Uuid,
    },
    Finalize {
        id:              Uuid,
        cert_pem:        Vec<u8>,
        chain_pem:       Vec<Vec<u8>>,
        controller_pem:  Vec<u8>,
        controller_uuid: Uuid,
    },
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
#[cfg(feature = "server")]
pub use server::PeerCerts;

#[cfg(feature = "client")]
pub use client::ClientCluster as Default_ClientCluster;

#[cfg(feature = "server")]
pub use server::ServerCluster as Default_ServerCluster;

#[cfg(feature = "server")]
pub mod _reexports {
    pub use actix_web::{
        web::{post, resource, Data, Json, ServiceConfig},
        HttpMessage, HttpRequest, HttpResponse, Responder,
    };
    pub use tokio::{
        fs,
        sync::{mpsc::Sender, RwLock},
    };
}
