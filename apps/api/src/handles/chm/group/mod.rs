mod types;

use actix_web::{delete, get, patch, post, put, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

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
async fn _get_group_root() -> HttpResponse {
    let mut map = HashMap::new();
    map.insert(
        "gid01".to_string(),
        GroupEntry { groupname: "dev".into(), users: vec!["alice".into(), "bob".into()] },
    );
    let body = GroupsCollection { groups: map };
    HttpResponse::Ok().json(body)
}

/// POST /api/chm/group
#[post("")]
async fn _post_group_root(data: web::Json<CreateGroupRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Group created".into() })
}

/// PUT /api/chm/group
#[put("")]
async fn _put_group_root(data: web::Json<PutGroupsRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Groups replaced".into() })
}

/// PATCH /api/chm/group
#[patch("")]
async fn _patch_group_root(data: web::Json<PatchGroupsRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Groups updated".into() })
}

/// DELETE /api/chm/group
#[delete("")]
async fn _delete_group_root(data: web::Json<DeleteGroupRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Group deleted".into() })
}
