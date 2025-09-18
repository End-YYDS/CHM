#[cfg(feature = "server")]
#[macro_export]
macro_rules! declare_init_route {
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

#[cfg(feature = "client")]
#[macro_export]
macro_rules! init_with {
    ($client:expr, $data:expr $(,)?) => {{
        use std::error::Error as _;
        use $crate::{ApiResponse, InitEnvelope};
        let __http = $client.build().await?;
        let __otp = $client.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let __payload = InitEnvelope { code: __otp, data: $data };
        let __url = format!("{}/init", $client.base_url());
        tracing::debug!("初始化請求 URL: {}", __url);
        let __resp = __http.post(__url).json(&__payload).send().await?;
        let __resp = __resp.error_for_status().map_err(|e| {
            tracing::error!("初始化 HTTP 錯誤: {e}");
            e
        })?;
        let __api_resp: ApiResponse = __resp.json().await.map_err(|e| {
            tracing::error!("初始化回應 JSON 解析失敗: {e}");
            e
        })?;
        if !__api_resp.ok {
            let __msg = __api_resp.message.clone();
            tracing::error!("初始化失敗: {}", __msg);
            Err::<(), Box<dyn std::error::Error + Send + Sync>>(__msg.into())
        } else {
            println!("{:#?}", __api_resp);
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
    }};
    ($client:expr, $data:expr, as $resp_ty:ty $(,)?) => {{
        use std::error::Error as _;
        use $crate::InitEnvelope;
        let __http = $client.build().await?;
        let __otp = $client.get_otp().map_err(|e| {
            tracing::error!("OTP Error: {}", e);
            e
        })?;
        let __payload = InitEnvelope { code: __otp, data: $data };
        let __url = format!("{}/init", $client.base_url());
        tracing::debug!("初始化請求 URL: {}", __url);
        let __resp = __http.post(&__url).json(&__payload).send().await?;
        let __resp = __resp.error_for_status().map_err(|e| {
            tracing::error!("初始化 HTTP 錯誤: {e}");
            e
        })?;
        let __parsed: $resp_ty = __resp.json().await.map_err(|e| {
            tracing::error!("初始化回應 JSON 解析失敗: {e}");
            e
        })?;
        Ok::<$resp_ty, Box<dyn std::error::Error + Send + Sync>>(__parsed)
    }};
}
