mod types;

use actix_web::{get, put, web, Scope};
use chm_grpc::restful;
use std::convert::TryFrom;

use crate::{
    commons::{ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use types::*;

pub fn values_scope() -> Scope {
    web::scope("/values").service(_get_values_root).service(_put_values_root)
}

/// GET /api/chm/setting/values
#[get("")]
async fn _get_values_root(app_state: web::Data<AppState>) -> RestfulResult<web::Json<Values>> {
    let mut client = app_state.gclient.clone();
    let resp = client.get_setting_values(restful::GetSettingValuesRequest {}).await?.into_inner();
    let values = resp.values.map(Values::from).unwrap_or_default();
    Ok(web::Json(values))
}

/// PUT /api/chm/setting/values
#[put("")]
async fn _put_values_root(
    app_state: web::Data<AppState>,
    data: web::Json<ValuesUpdate>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let req = data.into_inner().into_grpc();
    let resp = client.put_setting_values(req).await?.into_inner();
    let result = restful::put_setting_values_response::ResultType::try_from(resp.r#type)
        .unwrap_or(restful::put_setting_values_response::ResultType::Err);
    let response_type = match result {
        restful::put_setting_values_response::ResultType::Ok => ResponseType::Ok,
        _ => ResponseType::Err,
    };
    Ok(web::Json(ResponseResult { r#type: response_type, message: resp.message }))
}
