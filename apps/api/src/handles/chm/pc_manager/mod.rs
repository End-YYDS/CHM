use crate::{
    commons::ResponseResult,
    handles::chm::pc_manager::types::{
        DeletePcGroupRequest, DeletePcRequest, DeletePcResponse, GetPcgroupResponseResult,
        PCManagerRequest, PatchPcgroupRequest, PcInformation, PostPcgroupRequest,
        PutPcgroupRequest, RebootPcResponse, ShutdownPcResponse, SpecificRequest, UuidsRequest,
    },
    AppState,
};
use actix_web::{delete, get, patch, post, put, web, Scope};
use chm_grpc::{
    restful::{CreatePcGroupRequest, GetAllPcsRequest, GetPcGroupsRequest, GetSpecificPcsRequest},
    tonic,
};

mod translate;
pub mod types;

pub fn pc_manager_scope() -> Scope {
    web::scope("/pc")
        .service(delete_pc)
        .service(add)
        .service(all)
        .service(specific)
        .service(reboot)
        .service(shutdown)
}

pub fn pcgroup_scope() -> Scope {
    web::scope("/pcgroup")
        .service(post_pcgroup)
        .service(get_pcgroup)
        .service(put_pcgroup)
        .service(patch_pcgroup)
        .service(delete_pcgroup)
}

#[post("/add")]
async fn add(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PCManagerRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::AddPcRequest = data.into();
    let resp = client
        .add_pc(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .result
        .unwrap()
        .into();

    Ok(web::Json(resp))
}

#[get("/all")]
async fn all(app_state: web::Data<AppState>) -> actix_web::Result<web::Json<PcInformation>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_all_pcs(GetAllPcsRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[get("/specific")]
async fn specific(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<SpecificRequest>,
) -> actix_web::Result<web::Json<PcInformation>> {
    let mut client = app_state.gclient.clone();
    let data: GetSpecificPcsRequest = data.into();
    let resp = client
        .get_specific_pcs(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[delete("")]
async fn delete_pc(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeletePcRequest>,
) -> actix_web::Result<web::Json<DeletePcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::DeletePcsRequest = data.into();
    let resp = client
        .delete_pcs(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[post("/reboot")]
async fn reboot(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<UuidsRequest>,
) -> actix_web::Result<web::Json<RebootPcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::RebootPcsRequest = data.into();
    let resp = client
        .reboot_pcs(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[post("/shutdown")]
async fn shutdown(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<UuidsRequest>,
) -> actix_web::Result<web::Json<ShutdownPcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::ShutdownPcsRequest = data.into();
    let resp = client
        .shutdown_pcs(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[post("")]
async fn post_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PostPcgroupRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: CreatePcGroupRequest = data.into();
    let resp = client
        .create_pc_group(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[get("")]
async fn get_pcgroup(
    app_state: web::Data<AppState>,
) -> actix_web::Result<web::Json<GetPcgroupResponseResult>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_pc_groups(GetPcGroupsRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[put("")]
async fn put_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PutPcgroupRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::PutPcGroupRequest = data.into();
    let resp = client
        .put_pc_group(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[patch("")]
async fn patch_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PatchPcgroupRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::PatchPcGroupRequest = data.into();
    let resp = client
        .patch_pc_group(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[delete("")]
async fn delete_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeletePcGroupRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::DeletePcGroupRequest = data.into();
    let resp = client
        .delete_pc_group(data)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC 連線中斷: {}", status.message()))
            }
            _ => actix_web::error::ErrorInternalServerError(format!(
                "gRPC 失敗: {}",
                status.message()
            )),
        })?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}
