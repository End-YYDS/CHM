mod translate;
mod types;
use actix_web::{delete, get, patch, post, put, web, Scope};
use std::collections::HashMap;

use crate::{
    commons::{translate::AppError, ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use chm_grpc::restful::{
    CreateUserRequest as Grpc_CreateUserRequest, GetUsersRequest as Grpc_GetUsersRequest,
    PutUsersRequest as Grpc_PutUsersRequest, UserEntry as Grpc_UserEntry,
    UserPatch as Grpc_UserPatch,
};
use types::{
    CreateUserRequest as Web_CreateUserRequest, GetUserEntry as Web_GetUserEntry,
    PutUsersRequest as Web_PutUsersRequest, *,
};

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
async fn _get_user_root(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<UsersCollection>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_users(Grpc_GetUsersRequest {})
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let users = resp
        .users
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect::<HashMap<String, Web_GetUserEntry>>();
    let length = usize::try_from(resp.length)
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?;
    Ok(web::Json(UsersCollection { users, length }))
}

/// POST /api/chm/user
#[post("")]
async fn _post_user_root(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_CreateUserRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    // TDOO: 修正前端API傳送邏輯
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let user = Grpc_UserEntry {
        username: data.username,
        password: data.password,
        cn: data.cn,
        sn: data.sn,
        home_directory: data.home_directory,
        shell: data.shell,
        given_name: data.given_name,
        display_name: data.display_name,
        gid_number: "".to_string(),
        group: data.group,
        gecos: data.gecos,
    };
    let grpc_req = Grpc_CreateUserRequest { user: Some(user) };
    let resp = client
        .create_user(grpc_req)
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type: chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}

/// PUT /api/chm/user  （整筆）
#[put("")]
async fn _put_user_root(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_PutUsersRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    if data.data.is_empty() {
        return Ok(web::Json(ResponseResult {
            r#type: ResponseType::Err,
            message: "At least one user entry is required".into(),
        }));
    }
    let users = data
        .data
        .into_iter()
        .map(|(uid, entry)| {
            (
                uid,
                chm_grpc::restful::UserEntry {
                    username: "".to_string(), // username 不變
                    password: entry.password,
                    cn: entry.cn,
                    sn: entry.sn,
                    home_directory: entry.home_directory,
                    shell: entry.shell,
                    given_name: entry.given_name,
                    display_name: entry.display_name,
                    gid_number: "".to_string(), // 如果不用改 primary group
                    group: entry.group,
                    gecos: entry.gecos,
                },
            )
        })
        .collect();
    let grpc_req = Grpc_PutUsersRequest { users };
    let resp = client
        .put_users(grpc_req)
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type: chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}

/// PATCH /api/chm/user  （單一內容）
#[patch("")]
async fn _patch_user_root(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<PatchUsersRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let (username, user) = data
        .data
        .iter()
        .next()
        .ok_or_else(|| AppError::BadRequest("At least one user entry is required".to_string()))
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?;
    let mut data: Grpc_UserPatch = Grpc_UserPatch::default();
    if let Some(u) = &user.password {
        data.password = Some(u.clone());
    }
    if let Some(u) = &user.cn {
        data.cn = Some(u.clone());
    }
    if let Some(u) = &user.sn {
        data.sn = Some(u.clone());
    }
    if let Some(u) = &user.home_directory {
        data.home_directory = Some(u.clone());
    }
    if let Some(u) = &user.shell {
        data.shell = Some(u.clone());
    }
    if let Some(u) = &user.given_name {
        data.given_name = Some(u.clone());
    }
    if let Some(u) = &user.display_name {
        data.display_name = Some(u.clone());
    }
    if let Some(u) = &user.gecos {
        data.gecos = Some(u.clone());
    }
    if !user.group.is_empty() {
        data.group = user.group.clone();
    }
    let users = HashMap::from([(username.clone(), data)]);

    let resp = client
        .patch_users(chm_grpc::restful::PatchUsersRequest { users })
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type: chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}

/// DELETE /api/chm/user
#[delete("")]
async fn _delete_user_root(
    app_state: web::Data<AppState>,
    payload: web::Json<DeleteUserRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let resp = client
        .delete_user(chm_grpc::restful::DeleteUserRequest { uid: data.uid.clone() })
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type: chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}
