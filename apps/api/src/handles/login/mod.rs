#![allow(unused)]

use crate::commons::{ResponseResult, ResponseType};
use actix_session::Session;
use actix_web::{get, post, web, HttpResponse};
use serde::Deserialize;

#[post("")]
async fn login(session: Session, data: web::Json<LoginRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    if data.username != "admin" || data.password != "password" {
        return web::Json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Invalid credentials".to_string(),
        });
    }
    session.insert("uid", "1").unwrap();
    session.insert("username", data.username.clone()).ok();
    session.insert("role", "admin").ok(); // 例子
    session.renew();
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Login successful".to_string() })
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
