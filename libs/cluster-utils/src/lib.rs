use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse {
    message: String,
    ok: bool,
}
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "client")]
#[async_trait::async_trait]
pub trait ClusterClient {
    async fn init(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(feature = "client")]
pub use client::ClientCluster as Default_ClientCluster;

#[cfg(feature = "server")]
#[async_trait::async_trait]
pub trait ClusterServer {
    async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(feature = "server")]
pub use server::ServerCluster as Default_ServerCluster;
