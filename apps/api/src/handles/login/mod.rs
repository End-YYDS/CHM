#![allow(unused)]
use crate::commons::{ResponseResult, ResponseType};
use actix_web::{get, post, web};
use serde::Deserialize;

#[post("")]
async fn login(data: web::Json<LoginRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    if data.username != "admin" || data.password != "password" {
        return web::Json(ResponseResult {
            r#type:  ResponseType::Err,
            message: "Invalid credentials".to_string(),
        });
    }
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Login successful".to_string() })
}

#[get("/test")]
async fn test_login() -> impl actix_web::Responder {
    "Test login endpoint"
}

pub fn login_scope() -> actix_web::Scope {
    web::scope("/login").service(login).service(test_login)
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Password")]
    password: String,
}
