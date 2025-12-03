mod translate;
mod types;

use crate::{
    commons::{translate::AppError, ResponseResult},
    handles::software::translate::ActionResponseExt,
    AppState, RestfulResult,
};
use actix_web::{delete, get, post, web, Scope};
use chm_grpc::restful::{
    DeleteSoftwareRequest as GrpcDeleteSoftwareRequest,
    GetSoftwareRequest as GrpcGetSoftwareRequest,
    InstallSoftwareRequest as GrpcInstallSoftwareRequest,
};
use types::*;
use utoipa::OpenApi;

pub fn software_scope() -> Scope {
    web::scope("/software").service(get_software).service(post_software).service(delete_software)
}
#[derive(OpenApi)]
#[openapi(
    paths(get_software, post_software, delete_software),
    // components(schemas(
    //     DePutVxlanid,
    //     DePatchVxlanid,
    //     PatchPcgroupRequest,
    //     PutPcgroupRequest,
    // )),
    tags(
        (name = "Software Manager", description = "Software 管理相關 API")
    )
)]
pub struct SoftWareApiDoc;

/// GET /api/software
#[utoipa::path(
    get,
    path = "/software",
    tag = "Software Manager",
    responses(
        (status = 200, description = "取得所有套件", body = GetSoftwareResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("")]
async fn get_software(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<GetSoftwareResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_software(GrpcGetSoftwareRequest {})
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .into();
    Ok(web::Json(resp))
}

/// POST /api/software
#[utoipa::path(
    post,
    path = "/software",
    tag = "Software Manager",
    request_body = InstallRequest,
    responses(
        (status = 200, description = "添加成功", body = ActionResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("")]
async fn post_software(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<InstallRequest>,
) -> RestfulResult<web::Json<ActionResponse>> {
    let mut client = app_state.gclient.clone();
    let req = GrpcInstallSoftwareRequest {
        uuids:    data.uuids,
        packages: data.packages.unwrap_or_default(),
    };
    let resp = client
        .install_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into_action_response(PackageActionKind::Install)
        .inspect_err(|e: &AppError| tracing::error!(?e))?;
    Ok(web::Json(resp))
}

/// DELETE /api/software
#[utoipa::path(
    delete,
    path = "/software",
    tag = "Software Manager",
    request_body = DeleteRequest,
    responses(
        (status = 200, description = "刪除成功", body = ActionResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[delete("")]
async fn delete_software(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<DeleteRequest>,
) -> RestfulResult<web::Json<ActionResponse>> {
    let mut client = app_state.gclient.clone();
    let req = GrpcDeleteSoftwareRequest {
        uuids:    data.uuids,
        packages: data.packages.unwrap_or_default(),
    };
    let resp = client
        .delete_software(req)
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner()
        .try_into_action_response(PackageActionKind::Delete)
        .inspect_err(|e: &AppError| tracing::error!(?e))?;
    Ok(web::Json(resp))
}
