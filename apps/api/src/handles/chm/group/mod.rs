mod translate;
mod types;
use actix_web::{delete, get, patch, post, put, web, Scope};
use std::collections::HashMap;
use utoipa::OpenApi;

use crate::{
    commons::{translate::AppError, ResponseResult, ResponseType},
    AppState, RestfulResult,
};
use chm_grpc::restful::{
    CreateGroupRequest as Grpc_CreateGroupRequest, GetGroupsRequest as Grpc_GetGroupsRequest,
};
use types::{
    CreateGroupRequest as Web_CreateUserRequest, DeleteGroupRequest, GroupEntry as Web_GroupEntry,
    GroupsCollection as Web_GroupsCollection, PatchGroupEntry as Web_PatchGroupEntry,
    PatchGroupsRequest as Web_PatchGroupsRequest, PutGroupsRequest as Web_PutGroupsRequest,
};

pub fn group_scope() -> Scope {
    web::scope("/group")
        .service(get_group)
        .service(post_group)
        .service(put_group)
        .service(patch_group)
        .service(delete_group)
}

#[derive(OpenApi)]
#[openapi(
    paths(get_group, post_group, put_group,patch_group, delete_group),
    components(schemas(
        Web_GroupEntry,
        Web_PatchGroupEntry,
    )),
    tags(
        (name = "Groups", description = "群組 相關 API")
    )
)]
pub struct ChmGroupApiDoc;

/// GET /api/chm/group
#[utoipa::path(
    get,
    path = "/chm/group",
    tag = "Groups",
    responses(
        (status = 200, body = Web_GroupsCollection),
    )
)]
#[get("")]
async fn get_group(
    app_state: web::Data<AppState>,
) -> RestfulResult<web::Json<Web_GroupsCollection>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_groups(Grpc_GetGroupsRequest {})
        .await
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
#[utoipa::path(
    post,
    path = "/chm/group",
    tag = "Groups",
    request_body = Web_CreateUserRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[post("")]
async fn post_group(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_CreateUserRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let grpc_req = Grpc_CreateGroupRequest { groupname: data.groupname, users: data.users };
    let resp =
        client.create_group(grpc_req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type:  chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}

/// PUT /api/chm/group
#[utoipa::path(
    put,
    path = "/chm/group",
    tag = "Groups",
    request_body = Web_PutGroupsRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[put("")]
async fn put_group(
    app_state: web::Data<AppState>,
    payload: web::Json<Web_PutGroupsRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    if data.data.is_empty() {
        return Ok(web::Json(ResponseResult {
            r#type:  ResponseType::Err,
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
    let resp = client.put_groups(grpc_req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type:  chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}
/// PATCH /api/chm/group
#[utoipa::path(
    patch,
    path = "/chm/group",
    tag = "Groups",
    request_body = Web_PatchGroupsRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[patch("")]
async fn patch_group(
    app_state: web::Data<AppState>,
    web::Json(data): web::Json<Web_PatchGroupsRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let (gid, group_entry) = data
        .groups
        .iter()
        .next()
        .ok_or_else(|| AppError::BadRequest("At least one group entry is required".to_string()))
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
            r#type:  ResponseType::Err,
            message: "No field provided for update".into(),
        }));
    }
    let groups = HashMap::from([(gid.clone(), grpc_patch)]);
    let grpc_req = chm_grpc::restful::PatchGroupsRequest { groups };
    let resp =
        client.patch_groups(grpc_req).await.inspect_err(|e| tracing::error!(?e))?.into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type:  chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}

/// DELETE /api/chm/group
#[utoipa::path(
    delete,
    path = "/chm/group",
    tag = "Groups",
    request_body = DeleteGroupRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[delete("")]
async fn delete_group(
    app_state: web::Data<AppState>,
    payload: web::Json<DeleteGroupRequest>,
) -> RestfulResult<web::Json<ResponseResult>> {
    let data = payload.into_inner();
    let mut client = app_state.gclient.clone();
    let resp = client
        .delete_group(chm_grpc::restful::DeleteGroupRequest { gid: data.gid.clone() })
        .await
        .inspect_err(|e| tracing::error!(?e))?
        .into_inner();
    let result = resp.result.unwrap_or(chm_grpc::common::ResponseResult {
        r#type:  chm_grpc::common::ResponseType::Err as i32,
        message: "Unknown error".into(),
    });
    Ok(web::Json(result.into()))
}
