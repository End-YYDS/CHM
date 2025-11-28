use actix_web::{get, post, web};
use chm_grpc::{common, restful};
use std::{collections::HashMap, convert::TryFrom};

use crate::{
    commons::{translate::AppError, CommonInfo, ResponseResult, ResponseType, Status},
    handles::server::{
        apache::apache_scope,
        bind::bind_scope,
        dhcp::dhcp_scope,
        ftp::ftp_scope,
        ldap::ldap_scope,
        mysql::mysql_scope,
        nginx::nginx_scope,
        samba::samba_scope,
        squid::squid_scope,
        ssh::ssh_scope,
        stall::{stall_request, stalledResponse, stalled_request, Pcs},
    },
    AppState, RestfulResult,
};

pub mod apache;
pub mod bind;
pub mod dhcp;
pub mod ftp;
pub mod ldap;
pub mod mysql;
pub mod nginx;
pub mod samba;
pub mod squid;
pub mod ssh;
pub mod stall;

pub fn server_scope() -> actix_web::Scope {
    web::scope("/server")
        .service(apache_scope())
        .service(bind_scope())
        .service(dhcp_scope())
        .service(ldap_scope())
        .service(mysql_scope())
        .service(nginx_scope())
        .service(ftp_scope())
        .service(samba_scope())
        .service(squid_scope())
        .service(ssh_scope())
        .service(installed)
        .service(noinstall)
        .service(install)
}

#[allow(clippy::result_large_err)]
pub(crate) fn validate_server_name(raw: &str) -> RestfulResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Server 名稱不可為空".into()));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn convert_common_info(info: common::CommonInfo) -> CommonInfo {
    let status = match common::Status::try_from(info.status).unwrap_or(common::Status::Unspecified)
    {
        common::Status::Active => Status::Active,
        common::Status::Stopped => Status::Stopped,
        common::Status::Uninstalled => Status::Uninstalled,
        _ => Status::Stopped,
    };
    let ip = if info.ip.trim().is_empty() { None } else { Some(info.ip) };
    CommonInfo { hostname: info.hostname, status, cpu: info.cpu, memory: info.memory, ip }
}

pub(crate) fn convert_action_result(result: common::ActionResult) -> ResponseResult {
    let r#type = match result.r#type() {
        common::action_result::Type::Ok => ResponseType::Ok,
        common::action_result::Type::Err => ResponseType::Err,
        common::action_result::Type::Unspecified => ResponseType::Unspecified,
    };
    ResponseResult { r#type, message: result.message }
}

#[get("/installed")]
async fn installed(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<stalled_request>,
) -> RestfulResult<web::Json<stalledResponse>> {
    let server = validate_server_name(&payload.server)?;
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_server_installed_pcs(restful::GetServerInstalledPcsRequest { server })
        .await?
        .into_inner();
    let pcs_map = resp
        .pcs
        .into_iter()
        .map(|(uuid, info)| (uuid, convert_common_info(info)))
        .collect::<HashMap<_, _>>();
    let length = usize::try_from(resp.length).unwrap_or(pcs_map.len());
    Ok(web::Json(stalledResponse { pcs: Pcs::Installed { uuids: pcs_map }, length }))
}

#[get("/noinstall")]
async fn noinstall(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<stalled_request>,
) -> RestfulResult<web::Json<stalledResponse>> {
    let server = validate_server_name(&payload.server)?;
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_server_not_installed_pcs(restful::GetServerNotInstalledPcsRequest { server })
        .await?
        .into_inner();
    let pcs_map =
        resp.pcs.into_iter().map(|(uuid, info)| (uuid, info.hostname)).collect::<HashMap<_, _>>();
    let length = usize::try_from(resp.length).unwrap_or(pcs_map.len());
    Ok(web::Json(stalledResponse { pcs: Pcs::NotInstalled { uuids: pcs_map }, length }))
}

#[post("/install")]
async fn install(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<stall_request>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let server = validate_server_name(&payload.server)?;
    if payload.uuids.is_empty() {
        return Err(AppError::BadRequest("至少需要一個目標 UUID".into()));
    }
    let mut client = app_state.gclient.clone();
    let req = restful::InstallServerRequest {
        server,
        uuids: payload.uuids.iter().map(|u| u.trim().to_string()).collect(),
    };
    let resp = client.install_server(req).await?.into_inner();
    let result = resp
        .result
        .map(convert_action_result)
        .unwrap_or(ResponseResult { r#type: ResponseType::Ok, message: String::new() });
    Ok(web::Json(result))
}
