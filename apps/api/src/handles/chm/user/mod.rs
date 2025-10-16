mod translate;
mod types;
use actix_web::{delete, get, patch, post, put, web, Scope};
use std::collections::HashMap;

use crate::{
    commons::{ResponseResult, ResponseType},
    AppState,
};
use chm_grpc::{
    restful::GetUsersRequest as Grpc_GetUsersRequest,
    tonic,
};
use types::{UserEntry as Web_UserEntry, *};

pub fn user_scope() -> Scope {
    web::scope("/user")
        .service(_get_user_root)
        .service(_post_user_root)
        .service(_put_user_root)
        .service(_patch_user_root)
        .service(_delete_user_root)
}

/// GET /api/chm/user
// #[get("")]
// async fn _get_user_root() -> HttpResponse {
//     let mut map = HashMap::new();
//     map.insert(
//         "uid01".to_string(),
//         UserEntry {
//             username:       "alice".into(),
//             group:          vec!["wheel".into(), "dev".into()],
//             home_directory: "/home/alice".into(),
//             shell:          "/bin/bash".into(),
//         },
//     );
//     let body = UsersCollection { length: map.len(), users: map };
//     HttpResponse::Ok().json(body)
// }
#[get("")]
async fn _get_user_root(
    app_state: web::Data<AppState>,
) -> actix_web::Result<web::Json<UsersCollection>> {
    let mut client = app_state.gclient.clone();

    // 呼叫 gRPC server 取得使用者列表
    let resp = client
        .get_users(Grpc_GetUsersRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    let users = resp
        .users
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect::<HashMap<String, Web_UserEntry>>();
    let length = usize::try_from(resp.length)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(UsersCollection { users, length }))
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
