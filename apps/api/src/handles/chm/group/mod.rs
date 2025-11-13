mod translate;
mod types;
use actix_web::{delete, get, patch, post, put, web, Scope};
use std::collections::HashMap;

use crate::{
    commons::{translate::AppError, ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use chm_grpc::restful::{
    CreateGroupRequest as Grpc_CreateGroupRequest, GetGroupsRequest as Grpc_GetGroupsRequest,
};
use types::{
    CreateGroupRequest as Web_CreateUserRequest, DeleteGroupRequest, GroupEntry as Web_GroupEntry,
    GroupsCollection as Web_GroupsCollection, PatchGroupsRequest as Web_PatchGroupsRequest,
    PutGroupsRequest as Web_PutGroupsRequest,
};

pub fn group_scope() -> Scope {
    web::scope("/group")
        .service(_get_group_root)
        .service(_post_group_root)
        .service(_put_group_root)
        .service(_patch_group_root)
        .service(_delete_group_root)
}

/// GET /api/chm/group
#[get("")]
async fn _get_group_root(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<Web_GroupsCollection>> {
    let mut client = app_state.gclient.clone();

    let resp = client
        .get_groups(Grpc_GetGroupsRequest {})
        .await
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let groups = resp
        .groups
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect::<HashMap<String, Web_GroupEntry>>();
    Ok(web::Json(Web_GroupsCollection { groups }))
}

/// POST /api/chm/group
#[post("")]
async fn _post_group_root(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_CreateUserRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let grpc_req = Grpc_CreateGroupRequest { groupname: data.groupname, users: data.users };
    let resp = client
        .create_group(grpc_req)
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

/// PUT /api/chm/group
#[put("")]
async fn _put_group_root(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_PutGroupsRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    if data.data.is_empty() {
        return Ok(web::Json(ResponseResult {
            r#type: ResponseType::Err,
            message: "At least one group entry is required".into(),
        }));
    }
    let groups = data
        .data
        .into_iter()
        .map(|(gid, entry)| {
            (gid, chm_grpc::restful::GroupInfo { groupname: entry.groupname, users: entry.users })
        })
        .collect();
    let grpc_req = chm_grpc::restful::PutGroupsRequest { groups };
    let resp = client
        .put_groups(grpc_req)
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
/// PATCH /api/chm/group
#[patch("")]
async fn _patch_group_root(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<Web_PatchGroupsRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let (gid, group_entry) = data
        .groups
        .iter()
        .next()
        .ok_or_else(|| AppError::BadRequest("At least one group entry is required".to_string()))
        .inspect(|ok| tracing::debug!(?ok))
        .inspect_err(|e| tracing::error!(?e))?;
    let mut grpc_patch = chm_grpc::restful::GroupPatch::default();
    if let Some(name) = &group_entry.groupname {
        grpc_patch.groupname = Some(name.clone());
    }
    if let Some(users) = &group_entry.users {
        grpc_patch.users = users.clone();
    }
    if grpc_patch.groupname.is_none() && grpc_patch.users.is_empty() {
        return Ok(web::Json(ResponseResult {
            r#type: ResponseType::Err,
            message: "No field provided for update".into(),
        }));
    }
    let groups = HashMap::from([(gid.clone(), grpc_patch)]);
    let grpc_req = chm_grpc::restful::PatchGroupsRequest { groups };
    let resp = client
        .patch_groups(grpc_req)
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

/// DELETE /api/chm/group
#[delete("")]
async fn _delete_group_root(
    app_state: web::Data<AppState>,
    payload: web::Json<DeleteGroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let resp = client
        .delete_group(chm_grpc::restful::DeleteGroupRequest { gid: data.gid.clone() })
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
