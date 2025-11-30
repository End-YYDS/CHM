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
        use $crate::_reexports::{post, resource, Responder, Sender, ServiceConfig, RwLock};
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
            tracing::debug!("初始化成功: {}", __api_resp.message);
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
                    tracing::debug!("初始化成功: {}", __parsed.message);
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

#[cfg(feature = "server")]
#[macro_export]
macro_rules! software_init_define {
    (kind=$kind:expr, health_name=$health_name:expr, server=$is_server:expr, need_controller=true) => {
        use $crate::_reexports::{HttpRequest, Data, Json, HttpResponse};
        use chm_project_const::uuid::Uuid;

        #[derive(Debug)]
        pub struct InitCarry {
            pub root_ca_path:    PathBuf,
            pub uuid:            Uuid,
            pub server_hostname: String,
            pub server_addr:     SocketAddrV4,
            pub private_key:     Vec<u8>,
            pub cert_info:       CertInfo,
        }

        impl InitCarry {
            pub fn new(
                root_ca_path: PathBuf,
                uuid: Uuid,
                server_hostname: String,
                server_addr: SocketAddrV4,
                private_key: Vec<u8>,
                cert_info: CertInfo,
            ) -> Arc<Self> {
                Arc::new(Self { root_ca_path, uuid, server_hostname, server_addr, private_key, cert_info })
            }
        }

        async fn init_data_handler(
            _req: &HttpRequest,
            Json(data): Json<InitData>,
            carry: Data<Arc<InitCarry>>,
        ) -> ControlFlow<HttpResponse, ()> {
            match data {
                InitData::Bootstrap { root_ca_pem, .. } => {
                    if let Err(e) = atomic_write(&carry.root_ca_path, &root_ca_pem).await {
                        tracing::error!("寫入 RootCA 憑證失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
                    }

                    let mut san_extend = carry.cert_info.san.clone();
                    san_extend.push(carry.server_addr.ip().to_string());
                    san_extend.push(carry.uuid.to_string());
                    let csr_pem = match CertUtils::generate_csr(
                        carry.private_key.clone(),
                        &carry.cert_info.country,
                        &carry.cert_info.state,
                        &carry.cert_info.locality,
                        ProjectConst::PROJECT_NAME,
                        format!("{}.chm.com", &carry.cert_info.cn).as_str(),
                        san_extend,
                    ) {
                        Ok(csr) => csr,
                        Err(e) => {
                            tracing::error!("生成 CSR 失敗: {:?}", e);
                            return ControlFlow::Break(api_resp!(InternalServerError "生成 CSR 失敗"));
                        }
                    };
                    let service_desp = ServiceDescriptor {
                        kind:        $kind,
                        uri:         format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
                        health_name: $health_name,
                        is_server:   $is_server,
                        hostname:    GlobalConfig::with(|cfg| cfg.server.hostname.clone()),
                        uuid:        carry.uuid,
                    };
                    let resp = BootstrapResp { csr_pem, socket: carry.server_addr, service_desp };
                    return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
                }
                InitData::Finalize { id, cert_pem, controller_pem, controller_uuid, .. } => {
                    if id != carry.uuid {
                        tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                        return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
                    }
                    if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                        tracing::error!("保存憑證失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "保存憑證失敗"));
                    }
                    GlobalConfig::update_with(|cfg| {
                        let cert = CertUtils::load_cert_from_bytes(&controller_pem)
                            .expect("無法載入剛接收的憑證");
                        cfg.extend.controller.serial =
                            CertUtils::cert_serial_sha256(&cert).expect("無法計算Serial");
                        cfg.extend.controller.fingerprint =
                            CertUtils::cert_fingerprint_sha256(&cert).expect("無法計算fingerprint");
                        cfg.extend.controller.uuid = controller_uuid;
                    });

                    if let Err(e) = GlobalConfig::save_config().await {
                        tracing::error!("保存配置檔案失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "保存配置檔案失敗"));
                    }
                    if let Err(e) = GlobalConfig::reload_config().await {
                        tracing::error!("重新載入配置檔案失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "重新載入配置檔案失敗"));
                    }
                    tracing::info!("初始化完成，已接收憑證");
                }
            }
            ControlFlow::Continue(())
        }
        declare_init_route!(init_data_handler, data = InitData, extras = (carry: Arc<InitCarry>));
    };

    (kind=$kind:expr, health_name=$health_name:expr, server=$is_server:expr, need_controller=false) => {
        use $crate::_reexports::{HttpRequest, Data, Json, HttpResponse};
        use chm_project_const::uuid::Uuid;

        #[derive(Debug)]
        pub struct InitCarry {
            pub root_ca_path:    PathBuf,
            pub uuid:            Uuid,
            pub server_hostname: String,
            pub server_addr:     SocketAddrV4,
            pub private_key:     Vec<u8>,
            pub cert_info:       CertInfo,
        }
        impl InitCarry {
            pub fn new(
                root_ca_path: PathBuf,
                uuid: Uuid,
                server_hostname: String,
                server_addr: SocketAddrV4,
                private_key: Vec<u8>,
                cert_info: CertInfo,
            ) -> Arc<Self> {
                Arc::new(Self { root_ca_path, uuid, server_hostname, server_addr, private_key, cert_info })
            }
        }
        async fn init_data_handler(
            _req: &HttpRequest,
            Json(data): Json<InitData>,
            carry: Data<Arc<InitCarry>>,
        ) -> ControlFlow<HttpResponse, ()> {
            match data {
                InitData::Bootstrap { root_ca_pem, .. } => {
                    if let Err(e) = atomic_write(&carry.root_ca_path, &root_ca_pem).await {
                        tracing::error!("寫入 RootCA 憑證失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
                    }
                    let mut san_extend = carry.cert_info.san.clone();
                    san_extend.push(carry.uuid.to_string());
                    san_extend.push(carry.server_addr.ip().to_string());

                    let csr_pem = match CertUtils::generate_csr(
                        carry.private_key.clone(),
                        &carry.cert_info.country,
                        &carry.cert_info.state,
                        &carry.cert_info.locality,
                        ProjectConst::PROJECT_NAME,
                        format!("{}.chm.com", &carry.cert_info.cn).as_str(),
                        san_extend,
                    ) {
                        Ok(csr) => csr,
                        Err(e) => {
                            tracing::error!("生成 CSR 失敗: {:?}", e);
                            return ControlFlow::Break(api_resp!(InternalServerError "生成 CSR 失敗"));
                        }
                    };

                    let service_desp = ServiceDescriptor {
                        kind:        $kind,
                        uri:         format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
                        health_name: $health_name,
                        is_server:   $is_server,
                        hostname:    ID.to_string(),
                        uuid:        carry.uuid,
                    };
                    let resp = BootstrapResp { csr_pem, socket: carry.server_addr, service_desp };
                    return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
                }

                InitData::Finalize { id, cert_pem, .. } => {
                    if id != carry.uuid {
                        tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                        return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
                    }

                    if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                        tracing::error!("保存憑證失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "保存憑證失敗"));
                    }

                    if let Err(e) = GlobalConfig::save_config().await {
                        tracing::error!("保存配置檔案失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "保存配置檔案失敗"));
                    }
                    if let Err(e) = GlobalConfig::reload_config().await {
                        tracing::error!("重新載入配置檔案失敗: {:?}", e);
                        return ControlFlow::Break(api_resp!(InternalServerError "重新載入配置檔案失敗"));
                    }
                    tracing::info!("初始化完成，已接收憑證");
                }
            }
            ControlFlow::Continue(())
        }
        declare_init_route!(init_data_handler, data = InitData, extras = (carry: Arc<InitCarry>));
    };
}

#[cfg(feature = "server")]
#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! server_init {
    () => {{
        use chm_cert_utils::CertUtils;
        use chm_grpc::tonic::{Request, Status};
        fn check_is_controller(
            controller_args: (String, String),
        ) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static
        {
            move |req: Request<()>| {
                let peer_der_vec =
                    req.peer_certs().ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
                let leaf = peer_der_vec
                    .as_ref()
                    .as_slice()
                    .first()
                    .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;

                let x509 = CertUtils::load_cert_from_bytes(leaf)
                    .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))?;
                let serial = CertUtils::cert_serial_sha256(&x509)
                    .map_err(|e| Status::internal(format!("Serial sha256 failed: {e}")))?;
                let fingerprint = CertUtils::cert_fingerprint_sha256(&x509)
                    .map_err(|e| Status::internal(format!("Fingerprint sha256 failed: {e}")))?;

                if serial != controller_args.0 || fingerprint != controller_args.1 {
                    return Err(Status::permission_denied("Only controller cert is allowed"));
                }
                Ok(req)
            }
        }
        let (addr, rootca, cert_info, otp_len, otp_time, self_uuid, key_path, cert_path) =
            GlobalConfig::with(|cfg| {
                let host: Ipv4Addr = cfg.server.host.clone().parse().unwrap_or(Ipv4Addr::LOCALHOST);
                let port = cfg.server.port;
                let rootca = cfg.certificate.root_ca.clone();
                let cert_info = cfg.certificate.cert_info.clone();
                let otp_len = cfg.server.otp_len;
                let otp_time = cfg.server.otp_time;
                let uuid = cfg.server.unique_id;
                let key_path = cfg.certificate.client_key.clone();
                let cert_path = cfg.certificate.client_cert.clone();
                (
                    SocketAddrV4::new(host, port),
                    rootca,
                    cert_info,
                    otp_len,
                    otp_time,
                    uuid,
                    key_path,
                    cert_path,
                )
            });
        let (key, x509_cert) = CertUtils::generate_self_signed_cert(
            cert_info.bits,
            &cert_info.country,
            &cert_info.state,
            &cert_info.locality,
            &cert_info.org,
            &cert_info.cn,
            &cert_info.san,
            cert_info.days,
        )
        .map_err(|e| format!("生成自簽憑證失敗: {e}"))?;
        let carry = InitCarry::new(
            rootca.clone(),
            self_uuid,
            crate::ID.to_string(),
            addr,
            key.clone(),
            cert_info.clone(),
        );
        let init_server = chm_cluster_utils::Default_ServerCluster::new(
            addr.to_string(),
            x509_cert,
            key,
            None::<String>,
            otp_len,
            ID,
        )
        .with_otp_rotate_every(otp_time)
        .add_configurer(init_route())
        .with_app_data::<InitCarry>(carry.clone());
        tracing::info!("在 {addr} 啟動初始化 Server，等待 Controller 的初始化請求...");
        match init_server.init().await {
            ControlFlow::Continue(()) => {
                tracing::info!("初始化完成，啟動正式服務...");
            }
            ControlFlow::Break(e) => {
                tracing::warn!("初始化未完成，錯誤: {e}");
                return Ok(());
            }
        }
        tracing::info!("初始化 Server 已結束，繼續啟動正式服務...");
        (addr, rootca, key_path, cert_path, check_is_controller)
    }};
}
#[macro_export]
macro_rules! software_init {
    ($args_ty:ty) => {{
        // #[cfg(debug_assertions)]
        // let filter = tracing_subscriber::EnvFilter::from_default_env()
        //     .add_directive("info".parse().unwrap());
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        // #[cfg(not(debug_assertions))]
        // let filter = tracing_subscriber::EnvFilter::from_default_env();
        tracing_subscriber::fmt().with_env_filter(filter).init();
        let args: $args_ty = argh::from_env();
        if args.init_config {
            NEED_EXAMPLE.store(true, Relaxed);
            tracing::info!("初始化配置檔案...");
            config().await?;
            tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
            return Ok(());
        }
        config().await?;
        tracing::info!("配置檔案加載完成");
        args
    }};
}
