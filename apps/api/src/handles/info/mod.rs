mod translate;
mod types;

use crate::{commons::ResponseResult, AppState, RestfulResult};
use actix_web::{get, post, web, Scope};
use chm_grpc::restful;
use types::*;
use utoipa::OpenApi;

pub fn info_scope() -> Scope {
    web::scope("/info").service(get_info_all).service(post_info_get)
}

#[derive(OpenApi)]
#[openapi(
    paths(get_info_all, post_info_get),
    tags(
        (name = "Info", description = "DashBoard 相關 API")
    )
)]
pub struct InfoApiDoc;

/// GET /api/info/getAll
#[utoipa::path(
    get,
    path = "/info/getAll",
    tag = "Info",
    responses(
        (status = 200, description = "取得所有資訊", body = GetAllInfoResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/getAll")]
async fn get_info_all(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<GetAllInfoResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client.get_all_info(restful::GetAllInfoRequest {}).await?.into_inner();
    Ok(web::Json(GetAllInfoResponse::from(resp)))
}

/// POST /api/info/get

#[utoipa::path(
    post,
    path = "/info/get",
    tag = "Info",
    request_body = InfoGetRequest,
    responses(
        (status = 200, description = "取得資訊", body = InfoGetResponse),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("/get")]
async fn post_info_get(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<InfoGetRequest>,
) -> RestfulResult<web::Json<InfoGetResponse>> {
    let mut client = app_state.gclient.clone();
    let uuid = payload.uuid.and_then(|u| {
        let trimmed = u.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let target = payload
        .target
        .map(|t| restful::Target::from(t) as i32)
        .unwrap_or(restful::Target::Unspecified as i32);
    let req = restful::GetInfoRequest { target, uuid };
    let resp = client.get_info(req).await?.into_inner();
    Ok(web::Json(InfoGetResponse::from(resp)))
}
