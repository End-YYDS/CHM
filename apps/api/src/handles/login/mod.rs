#![allow(unused)]
use crate::commons::{ResponseResult, ResponseType};
use actix_web::{get, web};
use serde::Deserialize;

async fn login(data: web::Json<LoginRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Login successful".to_string() })
}

#[get("/test")]
async fn test_login() -> impl actix_web::Responder {
    "Test login endpoint"
}

pub fn login_scope() -> actix_web::Scope {
    actix_web::web::scope("/login")
        .route("", web::post().to(login))
        .route("/", web::post().to(login))
        .service(test_login)
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Password")]
    password: String,
}
