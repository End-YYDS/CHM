use std::{net::SocketAddr, str::FromStr};

use crate::{
    AppState, RestfulResult, commons::{ResponseResult, translate::AppError}, handles::chm::pc_manager::types::{
        DePatchVxlanid, DePutVxlanid, DeletePcGroupRequest, DeletePcRequest, DeletePcResponse, GetPcgroupResponseResult, PCManagerRequest, PatchPcgroupRequest, PcInformation, PostPcgroupRequest, PutPcgroupRequest, RebootPcResponse, ShutdownPcResponse, SpecificRequest, UuidsRequest
    }
};
use actix_web::{delete, get, patch, post, put, web, Scope};
use chm_grpc::restful::{
    CreatePcGroupRequest, GetAllPcsRequest, GetPcGroupsRequest, GetSpecificPcsRequest,
};
use utoipa::OpenApi;

mod translate;
pub mod types;

pub fn pc_manager_scope() -> Scope {
    web::scope("/pc")
        .service(delete_pc)
        .service(add_pc)
        .service(get_all_pc)
        .service(get_specific_pc)
        .service(reboot_pc)
        .service(shutdown_pc)
}

pub fn pcgroup_scope() -> Scope {
    web::scope("/pcgroup")
        .service(post_pcgroup)
        .service(get_pcgroup)
        .service(put_pcgroup)
        .service(patch_pcgroup)
        .service(delete_pcgroup)
}

#[derive(OpenApi)]
#[openapi(
    paths(delete_pc, add_pc, get_all_pc, get_specific_pc, reboot_pc, shutdown_pc, post_pcgroup, get_pcgroup, put_pcgroup, patch_pcgroup, delete_pcgroup),
    components(schemas(
        DePutVxlanid,
        DePatchVxlanid,

    )),
    tags(
        (name = "PC Manager", description = "CHM PC 管理相關 API")
    )
)]
pub struct PcManagerApiDoc;

#[utoipa::path(
    post,
    path = "/chm/pc/add",
    tag = "PC Manager",
    request_body = PCManagerRequest,
    responses(
        (status = 200, description = "添加成功", body = ResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("/add")]
async fn add_pc(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PCManagerRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    fn is_valid_ip(input: &str) -> bool {
        SocketAddr::from_str(input).is_ok()
    }
    if !is_valid_ip(data.ip.as_str()) {
        return Err(AppError::InvalidIpAddress(data.ip.to_string()));
    }
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::AddPcRequest = data.into();
    dbg!(&data);
    let resp = client
        .add_pc(data)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .result
        .unwrap()
        .into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    get,
    path = "/chm/pc/all",
    tag = "PC Manager",
    responses(
        (status = 200, description = "取得所有主機", body = PcInformation),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/all")]
async fn get_all_pc(app_state: web::Data<AppState>) -> RestfulResult<web::Json<PcInformation>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_all_pcs(GetAllPcsRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    get,
    path = "/chm/pc/specific",
    tag = "PC Manager",
    params(
        SpecificRequest
    ),
    responses(
        (status = 200, description = "取得特定主機", body = PcInformation),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/specific")]
async fn get_specific_pc(
    app_state: web::Data<AppState>,
    web::Query(data): web::Query<SpecificRequest>,
) -> RestfulResult<web::Json<PcInformation>> {
    let mut client = app_state.gclient.clone();
    let data: GetSpecificPcsRequest = data.into();
    let resp = client
        .get_specific_pcs(data)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    delete,
    path = "/chm/pc",
    tag = "PC Manager",
    request_body = DeletePcRequest,
    responses(
        (status = 200, description = "刪除特定主機", body = DeletePcResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[delete("")]
async fn delete_pc(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeletePcRequest>,
) -> RestfulResult<web::Json<DeletePcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::DeletePcsRequest = data.into();
    let resp =
        client.delete_pcs(data).await.inspect_err(|e| tracing::error!(?e))?.into_inner().into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    post,
    path = "/chm/pc/reboot",
    tag = "PC Manager",
    request_body = UuidsRequest,
    responses(
        (status = 200, description = "重啟特定主機", body = RebootPcResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("/reboot")]
async fn reboot_pc(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<UuidsRequest>,
) -> RestfulResult<web::Json<RebootPcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::RebootPcsRequest = data.into();
    let resp =
        client.reboot_pcs(data).await.inspect_err(|e| tracing::error!(?e))?.into_inner().into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    post,
    path = "/chm/pc/shutdown",
    tag = "PC Manager",
    request_body = UuidsRequest,
    responses(
        (status = 200, description = "關閉特定主機", body = ShutdownPcResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("/shutdown")]
async fn shutdown_pc(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<UuidsRequest>,
) -> RestfulResult<web::Json<ShutdownPcResponse>> {
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::ShutdownPcsRequest = data.into();
    let resp =
        client.shutdown_pcs(data).await.inspect_err(|e| tracing::error!(?e))?.into_inner().into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    post,
    path = "/chm/pcgroup",
    tag = "PC Manager",
    request_body = PostPcgroupRequest,
    responses(
        (status = 200, description = "新增Group", body = ResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("")]
async fn post_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PostPcgroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: CreatePcGroupRequest = data.into();
    let resp = client
        .create_pc_group(data)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    get,
    path = "/chm/pcgroup",
    tag = "PC Manager",
    responses(
        (status = 200, description = "取得所有PC群組資訊", body = GetPcgroupResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("")]
async fn get_pcgroup(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<GetPcgroupResponseResult>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_pc_groups(GetPcGroupsRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    put,
    path = "/chm/pcgroup",
    tag = "PC Manager",
    request_body = PutPcgroupRequest,
    responses(
        (status = 200, description = "更新整筆Group", body = ResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[put("")]
async fn put_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PutPcgroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::PutPcGroupRequest = data.into();
    let resp =
        client.put_pc_group(data).await.inspect_err(|e| tracing::error!(?e))?.into_inner().into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    patch,
    path = "/chm/pcgroup",
    tag = "PC Manager",
    request_body = PatchPcgroupRequest,
    responses(
        (status = 200, description = "更新整筆Group", body = ResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[patch("")]
async fn patch_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PatchPcgroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::PatchPcGroupRequest = data.into();
    let resp =
        client.patch_pc_group(data).await.inspect_err(|e| tracing::error!(?e))?.into_inner().into();
    Ok(web::Json(resp))
}

#[utoipa::path(
    delete,
    path = "/chm/pcgroup",
    tag = "PC Manager",
    request_body = DeletePcGroupRequest,
    responses(
        (status = 200, description = "刪除Group", body = ResponseResult),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[delete("")]
async fn delete_pcgroup(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeletePcGroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut client = app_state.gclient.clone();
    let data: chm_grpc::restful::DeletePcGroupRequest = data.into();
    let resp = client
        .delete_pc_group(data)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}
