#![allow(unused)]

use crate::{
    auth::AuthUser,
    commons::{translate::AppError, ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};
use chm_grpc::{common::ResponseType as gResponseType, restful::LoginRequest as gLoginRequest};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

#[derive(OpenApi)]
#[openapi(
    paths(login, me),
    tags(
        (name = "Auth", description = "登入 / 身分驗證相關 API")
    )
)]
pub struct LoginApiDocs;

#[utoipa::path(
    post,
    path = "/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登入成功", body = ResponseResult,example = json!({
                "Type": "Ok",
                "Message": "Login successful"
            })),
        (status = 401, description = "未授權", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Invalid Username or Password"
            })),
        (status = 403, description = "禁止存取", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Forbidden"
            })),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[post("")]
async fn login(
    session: Session,
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<LoginRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    dbg!(&data);
    let mut h = app_state.gclient.clone();
    let resp = h
        .login(gLoginRequest { username: data.username.clone(), password: data.password })
        .await
        .inspect_err(|e| tracing::error!("gRPC login error: {e:?}"))
        .map_err(|e| AppError::Forbidden(e.message().to_string()))?
        .into_inner()
        .result
        .unwrap();
    dbg!(&resp);
    let is_success = gResponseType::try_from(resp.r#type)
        .map_err(|e| AppError::Other(e.to_string()))
        .inspect_err(|e| tracing::error!(?e))?
        == gResponseType::Ok;
    dbg!(is_success);
    if !is_success {
        return Err(AppError::Unauthorized("Invalid Username or Password".into()));
    }
    // Todo: 等dodo的get_users()完成
    session.renew();
    session.insert("uid", "1")?;
    session.insert("username", data.username)?;
    session.insert("role", "admin")?; // 例子

    Ok(web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Login successful".to_string(),
    }))
}

#[cfg(debug_assertions)]
#[get("/test")]
async fn test_login(_auth: crate::auth::RequireLogin) -> impl actix_web::Responder {
    "Test login endpoint (must be logged in)"
}

#[utoipa::path(
    get,
    path = "/login/me",
    tag = "Auth",
    responses(
        (status = 200, description = "登入資料取得成功", body = AuthUser,example = json!({
                "Uid": "1",
                "Username": "test",
                "Role":   "admin",
            })),
        (status = 401, description = "未授權", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Invalid Username or Password"
            })),
        (status = 403, description = "禁止存取", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Forbidden"
            })),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
#[get("/me")]
async fn me(user: crate::auth::AuthUser) -> RestfulResult<web::Json<AuthUser>> {
    Ok(web::Json(AuthUser { uid: user.uid, username: user.username, role: user.role }))
}

pub fn login_scope() -> actix_web::Scope {
    let route = web::scope("/login").service(login).service(me);
    #[cfg(debug_assertions)]
    let route = route.service(test_login);
    route
}

/// 登入請求
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct LoginRequest {
    username: String,
    password: String,
}
