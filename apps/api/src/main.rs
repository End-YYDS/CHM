use actix_cors::Cors;
use actix_session::{
    config::{PersistentSession, TtlExtensionPolicy},
    storage::CookieSessionStore,
    SessionMiddleware,
};
use actix_web::{
    cookie::{time::Duration as ac_Duration, Key, SameSite},
    http::header,
    middleware::Logger,
    web, App, HttpServer,
};
#[cfg(debug_assertions)]
use api_server::openapi::build_openapi;
use api_server::{
    config, configure_app, ApiResult, AppState, CertInfo, GlobalConfig, ID, NEED_EXAMPLE,
};
use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, server_init, software_init, software_init_define,
    BootstrapResp, InitData, ServiceDescriptor, ServiceKind,
};
use chm_grpc::{
    restful::restful_service_client::RestfulServiceClient,
    tonic::{
        codec::CompressionEncoding,
        transport::{Certificate, ClientTlsConfig, Endpoint, Identity},
    },
};
use chm_project_const::ProjectConst;
use openssl::ssl::{SslFiletype, SslMethod};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::ControlFlow,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Duration,
};
#[cfg(debug_assertions)]
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, FromArgs)]
/// API 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    init_config: bool,
}
software_init_define!(
    kind = ServiceKind::Api,
    health_name = None,
    server = false,
    need_controller = false
);

#[actix_web::main]
async fn main() -> ApiResult<()> {
    software_init!(Args);
    let (addr, rootca, key_path, cert_path, _check_is_controller) = server_init!();
    let (controller_addr, frontend_origin, cookie_name, secure_key_bytes, same_site, cookie_secure) =
        GlobalConfig::with(|cfg| {
            let controller_addr = cfg.extend.controller.clone();
            let frontend_origin = cfg.extend.security.frontend_origin.clone();
            let cookie_name = cfg.extend.security.cookie_name.clone();
            let secure_key =
                chm_password::decode_key64_from_base64(cfg.extend.security.session_key.as_str());
            let same_site = cfg.extend.security.same_site.clone();
            (
                controller_addr,
                frontend_origin,
                cookie_name,
                secure_key.expect("無效的 Session Key"),
                same_site,
                cfg.extend.security.cookie_secure,
            )
        });
    let identity = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
    let mut tls =
        ClientTlsConfig::new().identity(Identity::from_pem(identity.1, identity.0)).ca_certificate(
            Certificate::from_pem(std::fs::read(&rootca).expect("讀取 RootCA 憑證失敗")),
        );
    if cfg!(debug_assertions) {
        tls = tls.use_key_log();
    }
    // TODO: 將EndPoint需要先查詢DNS
    let endpoint = Endpoint::from_shared(controller_addr.clone())
        .map_err(|e| format!("無效的 Controller 地址: {e}"))
        .expect("建立 gRPC Endpoint 失敗")
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(60))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(5))
        .tls_config(tls)
        .expect("設定 TLS 失敗");
    let channel = endpoint.connect_lazy();
    let grpc_client = RestfulServiceClient::new(channel)
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);
    GlobalConfig::save_config().await.expect("保存配置檔案失敗");
    let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.set_certificate_file(cert_path, SslFiletype::PEM)?;
    let key = Key::from(&secure_key_bytes);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&frontend_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![header::CONTENT_TYPE, header::ACCEPT])
            .supports_credentials()
            .max_age(3600);
        let same_site =
            if same_site.eq_ignore_ascii_case("None") { SameSite::None } else { SameSite::Lax };
        let lifecycle = PersistentSession::default()
            .session_ttl(ac_Duration::minutes(30))
            .session_ttl_extension_policy(TtlExtensionPolicy::OnEveryRequest);
        let session_mw = SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
            .cookie_name(cookie_name.clone())
            .cookie_secure(cookie_secure)
            .cookie_http_only(true)
            .cookie_same_site(same_site)
            .session_lifecycle(lifecycle)
            .build();
        let app = App::new()
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                tracing::error!(?err, "JSON deserialization error");
                actix_web::error::ErrorBadRequest(err)
            }))
            .app_data(Data::new(AppState { gclient: grpc_client.clone() }))
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(session_mw)
            .configure(configure_app);
        #[cfg(debug_assertions)]
        let app = app
            .service(SwaggerUi::new("/docs/{_:.*}").url("/api-doc/openapi.json", build_openapi()));
        app
    })
    .bind_openssl(addr, builder)?
    .run()
    .await?;
    Ok(())
}
