#![allow(unused)]

use crate::{
    commons::{translate::AppError, ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};
use chm_grpc::{common::ResponseType as gResponseType, restful::LoginRequest as gLoginRequest};
use serde::Deserialize;

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
        .map_err(|e| AppError::Forbidden(e.message().to_string()))
        .inspect_err(|e| tracing::error!(?e))?
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
        r#type: ResponseType::Ok,
        message: "Login successful".to_string(),
    }))
}

#[cfg(debug_assertions)]
#[get("/test")]
async fn test_login(_auth: crate::auth::RequireLogin) -> impl actix_web::Responder {
    "Test login endpoint (must be logged in)"
}

#[get("/me")]
async fn me(user: crate::auth::AuthUser) -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "uid": user.uid,
        "username": user.username,
        "role": user.role
    })))
}

pub fn login_scope() -> actix_web::Scope {
    let route = web::scope("/login").service(login).service(me);
    #[cfg(debug_assertions)]
    let route = route.service(test_login);
    route
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Password")]
    password: String,
}
