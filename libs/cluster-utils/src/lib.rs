use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub message: String,
    pub ok:      bool,
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
    pub use tokio::{fs, sync::mpsc::Sender};
}
