#[cfg(feature = "server")]
#[macro_export]
macro_rules! declare_init_route {
    // ── 無 ret、無 extras ─────────────────────────────────────────────────────────
    ($handler:expr, data = $data:ty) => {
        $crate::declare_init_route!($handler, data = $data, extras = (), ret = ());
    };

    // ── 無 ret、有 extras ────────────────────────────────────────────────────
    ($handler:expr, data = $data:ty, extras = ($($extra_pat:ident : $extra_ty:ty),* $(,)?)) => {
        $crate::declare_init_route!($handler, data = $data, extras = ($($extra_pat : $extra_ty),*), ret = ());
    };

    // ── 有 ret、無 extras ────────────────────────────────────────────────────
    ($handler:expr, data = $data:ty, ret = $ret:ty) => {
        $crate::declare_init_route!($handler, data = $data, extras = (), ret = $ret);
    };

    // ── 有 ret、有 extras（總成版，實作都在這支）────────────────────────────
    ($handler:expr, data = $data:ty, extras = ($($extra_pat:ident : $extra_ty:ty),* $(,)?), ret = $ret:ty) => {
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::ops::ControlFlow;
        use $crate::_reexports::{post, resource, Data, HttpResponse, Json, Responder, Sender, ServiceConfig, HttpRequest,RwLock};
        use $crate::Value;

        pub fn init_route() -> impl Fn(&mut ServiceConfig) + Clone {
            let handler = $handler;
            move |cfg: &mut ServiceConfig| {
                cfg.service(resource("/init").route(post().to({
                    let handler = handler.clone();
                    move |req: HttpRequest,
                          shutdown_tx: Data<Sender<()>>,
                          marker_path: Data<PathBuf>,
                          otp_code: Data<Arc<RwLock<String>>>,
                          $($extra_pat : Data<$extra_ty>,)*
                          Json(envelope): Json<$crate::InitEnvelope<$data>>|
                    async move {
                        let current_otp = otp_code.read().await.clone();
                        if envelope.code.as_str() != current_otp {
                            return $crate::api_resp!(Unauthorized "OTP 驗證失敗");
                        }
                        let data_json = Json(envelope.data);
                        let pending_resp: HttpResponse = {
                            match handler(&req, data_json $(, $extra_pat.clone())*).await {
                                ControlFlow::Break(resp) => {
                                    return resp;
                                }
                                ControlFlow::Continue(val) => {
                                    $crate::__init_route_build_pending_resp!(val, $ret)
                                }
                            }
                        };
                        if let Err(e) = tokio::fs::write(marker_path.get_ref(), b"done").await {
                            return $crate::api_resp!(InternalServerError format!("寫入 marker 檔案失敗: {e}"));
                        }
                        let _ = shutdown_tx.send(()).await;
                        pending_resp
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

        let __resp = __http.post(&__url).json(&__payload).send().await?;
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
            tracing::info!("初始化成功: {}", __api_resp.message);
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
    }};
    ($client:expr, $data:expr, as $resp_ty:ty $(,)?) => {{
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

        let __resp = __http.post(&__url).json(&__payload).send().await?;
        let __resp = __resp.error_for_status().map_err(|e| {
            tracing::error!("初始化 HTTP 錯誤: {e}");
            e
        })?;
        let __parsed: ApiResponse<$resp_ty> = __resp.json().await.map_err(|e| {
            tracing::error!("初始化回應 JSON 解析失敗: {e}");
            e
        })?;

        if !__parsed.ok {
            let __msg = __parsed.message.clone();
            tracing::error!("初始化失敗: {}", __msg);
            Err::<$resp_ty, Box<dyn std::error::Error + Send + Sync>>(__msg.into())
        } else {
            match __parsed.data {
                Some(__val) => {
                    tracing::info!("初始化成功: {}", __parsed.message);
                    Ok::<$resp_ty, Box<dyn std::error::Error + Send + Sync>>(__val)
                }
                None => {
                    let __msg = "初始化成功但回傳缺少資料 (data=None)".to_string();
                    tracing::error!("{}", __msg);
                    Err::<$resp_ty, Box<dyn std::error::Error + Send + Sync>>(__msg.into())
                }
            }
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __init_route_build_pending_resp {
    ($val:ident, ()) => {{
        $crate::api_resp!(ok "初始化完成，web服務器將關閉")
    }};
    ($val:ident, $ret:ty) => {{
        $crate::api_resp!(ok "初始化完成，web服務器將關閉", $val)
    }};
}

#[macro_export]
macro_rules! api_resp {
    (ok $msg:expr) => {{
        $crate::_reexports::HttpResponse::Ok()
            .json($crate::ApiResponse::<$crate::Value>::ok_msg($msg))
    }};
    (ok $msg:expr, $data:expr) => {{
        $crate::_reexports::HttpResponse::Ok().json($crate::ApiResponse::ok_with($msg, $data))
    }};
    (BadRequest $msg:expr) => {{
        $crate::_reexports::HttpResponse::BadRequest()
            .json($crate::ApiResponse::<$crate::Value>::err($msg))
    }};
    (InternalServerError $msg:expr) => {{
        $crate::_reexports::HttpResponse::InternalServerError()
            .json($crate::ApiResponse::<$crate::Value>::err($msg))
    }};
    (Unauthorized $msg:expr) => {{
        $crate::_reexports::HttpResponse::Unauthorized()
            .json($crate::ApiResponse::<$crate::Value>::err($msg))
    }};
}
