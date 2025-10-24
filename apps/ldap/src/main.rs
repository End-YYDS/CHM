use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, server_init, software_init, software_init_define,
    BootstrapResp, InitData, ServiceDescriptor, ServiceKind,
};
use chm_grpc::{
    ldap::ldap_service_server::LdapServiceServer,
    tonic::{
        codec::CompressionEncoding,
        codegen::InterceptedService,
        transport::{Certificate, Identity, ServerTlsConfig},
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::ProjectConst;
use ldap::{config, service::MyLdapService, CertInfo, GlobalConfig, ID, NEED_EXAMPLE};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::ControlFlow,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::sync::watch;

#[derive(FromArgs, Debug, Clone)]
/// Ldap 主程式參數
pub struct Args {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    pub init_config: bool,
}
// TODO: 添加叢集交換的FN

// #[derive(Debug)]
// pub struct InitCarry {
//     pub root_ca_path:    PathBuf,
//     pub uuid:            Uuid,
//     pub server_hostname: String,
//     pub server_addr:     SocketAddrV4,
//     pub private_key:     Vec<u8>,
//     pub cert_info:       CertInfo,
// }
//
// impl InitCarry {
//     pub fn new(
//         root_ca_path: PathBuf,
//         uuid: Uuid,
//         server_hostname: String,
//         server_addr: SocketAddrV4,
//         private_key: Vec<u8>,
//         cert_info: CertInfo,
//     ) -> Arc<Self> {
//         Arc::new(Self { root_ca_path, uuid, server_hostname, server_addr,
// private_key, cert_info })     }
// }
//
// async fn init_data_handler(
//     _req: &HttpRequest,
//     Json(data): Json<InitData>,
//     carry: Data<Arc<InitCarry>>,
// ) -> ControlFlow<HttpResponse, ()> {
//     match data {
//         InitData::Bootstrap { root_ca_pem, .. } => {
//             if let Err(e) = atomic_write(&carry.root_ca_path,
// &root_ca_pem).await {                 tracing::error!("寫入 RootCA 憑證失敗:
// {:?}", e);                 return
// ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
//             }
//             let mut san_extend = carry.cert_info.san.clone();
//             san_extend.push(carry.uuid.to_string());
//             let csr_pem = match CertUtils::generate_csr(
//                 carry.private_key.clone(),
//                 &carry.cert_info.country,
//                 &carry.cert_info.state,
//                 &carry.cert_info.locality,
//                 ProjectConst::PROJECT_NAME,
//                 format!("{}.chm.com", &carry.cert_info.cn).as_str(),
//                 san_extend,
//             ) {
//                 Ok(csr) => csr,
//                 Err(e) => {
//                     tracing::error!("生成 CSR 失敗: {:?}", e);
//                     return ControlFlow::Break(api_resp!(InternalServerError
// "生成 CSR 失敗"));                 }
//             };
//             let service_desp = ServiceDescriptor {
//                 kind:        ServiceKind::Ldap,
//                 uri:         format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
//                 health_name: Some("ldap.LdapService".to_string()),
//                 is_server:   true,
//                 hostname:    ID.to_string(),
//                 uuid:        carry.uuid,
//             };
//             let resp = BootstrapResp { csr_pem, socket: carry.server_addr,
// service_desp };             return ControlFlow::Break(api_resp!(ok
// "初始化交換成功", resp));         }
//         InitData::Finalize { id, cert_pem, controller_pem, controller_uuid,
// .. } => {             if id != carry.uuid {
//                 tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
//                 return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
//             }
//             if let Err(e) = CertUtils::save_cert(ID, &carry.private_key,
// &cert_pem) {                 tracing::error!("保存憑證失敗: {:?}", e);
//                 return ControlFlow::Break(api_resp!(InternalServerError
// "保存憑證失敗"));             }
//             GlobalConfig::update_with(|cfg| {
//                 let cert =
//
// CertUtils::load_cert_from_bytes(&controller_pem).expect("
// 無法載入剛接收的憑證");                 cfg.extend.controller.serial =
//
// CertUtils::cert_serial_sha256(&cert).expect("無法計算Serial");
// cfg.extend.controller.fingerprint = CertUtils::cert_fingerprint_sha256(&cert)
//                     .expect(
//                         "
//             無法計算fingerprint",
//                     );
//                 cfg.extend.controller.uuid = controller_uuid;
//             });
//             if let Err(e) = GlobalConfig::save_config().await {
//                 tracing::error!("保存配置檔案失敗: {:?}", e);
//                 return ControlFlow::Break(api_resp!(InternalServerError
// "保存配置檔案失敗"));             }
//             if let Err(e) = GlobalConfig::reload_config().await {
//                 tracing::error!("重新載入配置檔案失敗: {:?}", e);
//                 return ControlFlow::Break(api_resp!(InternalServerError
// "重新載入配置檔案失敗"));             }
//             tracing::info!("初始化完成，已接收憑證");
//         }
//     }
//     ControlFlow::Continue(())
// }
// declare_init_route!(init_data_handler, data = InitData,extras = (carry:
// Arc<InitCarry>));

software_init_define!(
    kind = ServiceKind::Ldap,
    health_name = Some("ldap.LdapService".to_string()),
    server = true,
    need_controller = true
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    software_init!(Args);
    let (addr, rootca, key_path, cert_path, is_controller) = server_init!();
    let (ldap_url, bind_dn, bind_password) = GlobalConfig::with(|cfg| {
        (
            cfg.extend.ldap_settings.url.clone(),
            cfg.extend.ldap_settings.bind_dn.clone(),
            cfg.extend.ldap_settings.bind_password.clone(),
        )
    });
    tracing::info!("正在啟動Ldap...");
    let (_cert_update_tx, mut cert_update_rx) = watch::channel(());

    loop {
        let (key, cert) = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(CertUtils::load_cert(&rootca)?.to_pem()?));
        let (health_reporter, health_service) = health_reporter();

        health_reporter.set_serving::<LdapServiceServer<MyLdapService>>().await;
        let mut rx = cert_update_rx.clone();
        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("[gRPC] 收到 Ctrl-C，開始關閉...");
                    }
                    Ok(_) = rx.changed() => {
                        tracing::info!("[gRPC] 憑證更新，開始重新啟動 gRPC...");
                    }
                }
                health_reporter.set_not_serving::<LdapServiceServer<MyLdapService>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        // TODO: 加入cert_update_tx
        let server = MyLdapService::new(ldap_url.clone(), bind_dn.clone(), bind_password.clone());
        let raw_ldap = LdapServiceServer::new(server)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let ldap_svc = InterceptedService::new(raw_ldap, is_controller(controller_args));
        tracing::info!("Starting gRPC server on {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .add_service(ldap_svc)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);
        if let Err(e) = server.await {
            tracing::error!("[gRPC] 啟動失敗: {e:?}");
        }
        if cert_update_rx.has_changed().unwrap_or(false) {
            tracing::info!("[gRPC] 憑證更新，重新啟動 gRPC 服務");
            let _ = cert_update_rx.borrow_and_update();
            continue;
        }
        break;
    }
    Ok(())
}
