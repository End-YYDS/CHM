mod types;

use crate::{AppState, RestfulResult};
use actix_web::{get, post, web, Scope};
use chm_grpc::restful;
use types::*;

pub fn info_scope() -> Scope {
    web::scope("/info").service(_get_info_all).service(_post_info_get)
}

/// GET /api/info/getAll
#[get("/getAll")]
async fn _get_info_all(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<GetAllInfoResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client.get_all_info(restful::GetAllInfoRequest {}).await?.into_inner();
    Ok(web::Json(GetAllInfoResponse::from(resp)))
}

/// POST /api/info/get
#[post("/get")]
async fn _post_info_get(
    app_state: web::Data<AppState>,
    web::Json(payload): web::Json<InfoGetRequest>,
) -> RestfulResult<web::Json<InfoGetResponse>> {
    let mut client = app_state.gclient.clone();
    let uuid = payload.uuid.and_then(|u| {
        let trimmed = u.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let req = restful::GetInfoRequest {
        zone: restful::Zone::from(payload.zone) as i32,
        target: restful::Target::from(payload.target) as i32,
        uuid,
    };
    let resp = client.get_info(req).await?.into_inner();
    Ok(web::Json(InfoGetResponse::from(resp)))
}
