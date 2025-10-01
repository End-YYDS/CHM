mod types;

use actix_web::{delete, get, patch, post, put, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn user_scope() -> Scope {
    web::scope("/user")
        .service(_get_user_root)
        .service(_post_user_root)
        .service(_put_user_root)
        .service(_patch_user_root)
        .service(_delete_user_root)
}

/// GET /api/chm/user
#[get("")]
async fn _get_user_root() -> HttpResponse {
    let mut map = HashMap::new();
    map.insert(
        "uid01".to_string(),
        UserEntry {
            username:       "alice".into(),
            group:          vec!["wheel".into(), "dev".into()],
            home_directory: "/home/alice".into(),
            shell:          "/bin/bash".into(),
        },
    );
    let body = UsersCollection { length: map.len(), users: map };
    HttpResponse::Ok().json(body)
}

/// POST /api/chm/user
#[post("")]
async fn _post_user_root(data: web::Json<CreateUserRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "User created".into() })
}

/// PUT /api/chm/user  （整筆）
#[put("")]
async fn _put_user_root(data: web::Json<PutUsersRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Users replaced".into() })
}

/// PATCH /api/chm/user  （單一內容）
#[patch("")]
async fn _patch_user_root(data: web::Json<PatchUsersRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Users updated".into() })
}

/// DELETE /api/chm/user
#[delete("")]
async fn _delete_user_root(data: web::Json<DeleteUserRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "User deleted".into() })
}
