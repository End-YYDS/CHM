use chm_grpc::tonic::async_trait;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub message: String,
    pub ok:      bool,
}
#[derive(Deserialize, Debug, Clone)]
pub struct InitEnvelope<T> {
    pub code: String,
    #[serde(flatten)]
    pub data: T,
}
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "client")]
#[async_trait]
pub trait ClusterClient {
    async fn init(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(feature = "client")]
pub use client::ClientCluster as Default_ClientCluster;

#[cfg(feature = "server")]
#[async_trait]
pub trait ClusterServer {
    async fn init(&self) -> Result<InitResult, Box<dyn std::error::Error + Send + Sync>>;
}
#[cfg(feature = "server")]
pub use crate::server::InitResult;
#[cfg(feature = "server")]
pub use server::ServerCluster as Default_ServerCluster;

#[cfg(feature = "server")]
pub mod _reexports {
    pub use actix_web::{
        web::{post, resource, Data, Json, ServiceConfig},
        HttpResponse, Responder,
    };
    pub use tokio::{fs, sync::mpsc::Sender};
}

#[cfg(feature = "server")]
#[macro_export]
macro_rules! declare_init_route {
    // ($handler:expr, state = $state:ty)
    ($handler:expr, data = $data:ty) => {
        use actix_web::web;
        use std::path::PathBuf;
        use $crate::_reexports::{
            post, resource, Data, HttpResponse, Json, Responder, Sender, ServiceConfig,
        };
        pub fn init_route() -> impl Fn(&mut ServiceConfig) + Clone {
            let handler = $handler;
            move |cfg: &mut ServiceConfig| {
                cfg.service(resource("/init").route(post().to({
                    let handler = handler.clone();
                    move |req: HttpRequest,
                          shutdown_tx: Data<Sender<()>>,
                          marker_path: Data<PathBuf>,
                          otp_code: Data<String>,
                          Json(envelope): Json<$crate::InitEnvelope<$data>>| async move {
                        if envelope.code.as_str() != otp_code.as_str() {
                            return HttpResponse::Unauthorized().json($crate::ApiResponse {
                                message: "OTP 驗證失敗".into(),
                                ok:      false,
                            });
                        }
                        let data_json = Json(envelope.data);
                        if let ControlFlow::Break(resp) = handler(&req, data_json).await {
                            return resp;
                        }
                        if let Err(e) = tokio::fs::write(marker_path.get_ref(), b"done").await {
                            return HttpResponse::InternalServerError().json($crate::ApiResponse {
                                message: format!("寫入 marker 檔案失敗: {e}"),
                                ok:      false,
                            });
                        }
                        let _ = shutdown_tx.send(()).await;
                        HttpResponse::Ok().json(ApiResponse {
                            message: "初始化完成，web服務器將關閉".into(),
                            ok:      true,
                        })
                    }
                })));
            }
        }
    };
}
