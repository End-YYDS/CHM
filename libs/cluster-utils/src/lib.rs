use chm_project_const::uuid::Uuid;
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

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InitData {
    Bootstrap { root_ca_pem: Vec<u8> }, /* Controller 連線過來之後先傳送root_ca_pem,並且取得API
                                         * uuid 與 csr_pem 與Hostname 及 服務本身的Port */
    Finalize { id: Uuid, cert_pem: Vec<u8>, chain_pem: Vec<Vec<u8>> }, /* 檢查 Controller收到的UUID與自身是否相同，相同才接收憑證 */
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapResp {
    pub uuid:            Uuid,
    pub csr_pem:         Vec<u8>,
    pub server_hostname: String,
    pub server_port:     u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitEnvelope<T> {
    pub code: String,
    #[serde(flatten)]
    pub data: T,
}
#[cfg(feature = "client")]
mod client;
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
