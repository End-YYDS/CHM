mod types;

use crate::{
    commons::{ResponseResult, ResponseType},
    handles::chm::role::types::{
        Color, RoleDeleteRequest, RoleInfo, RolePatchRequest, RolePutResponse, RolesResponse,
        UsersResponse,
    },
};
use actix_web::{delete, get, patch, post, put, web, Scope};

#[get("")]
async fn _get_role_root() -> web::Json<RolesResponse> {
    let members = vec![1, 2, 3, 4];
    let member_length = members.len();
    let roles = vec![RoleInfo {
        name: "TEST".to_string(),
        permissions: 1 << 1,
        color: Color::Red,
        members,
        length: member_length,
    }];
    let length = roles.len();
    web::Json(RolesResponse { roles, length })
}

#[post("")]
async fn _post_role_root(data: web::Json<RoleInfo>) -> web::Json<ResponseResult> {
    println!("Received role data: {data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Role created successfully".to_string(),
    })
}
#[delete("")]
async fn _delete_role_root(data: web::Json<RoleDeleteRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: format!("Role '{}' deleted successfully", data.name),
    })
}
#[put("")]
async fn _put_role_root(data: web::Json<RolePutResponse>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Role updated successfully".to_string(),
    })
}
#[patch("")]
async fn _patch_role_root(data: web::Json<RolePatchRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Role patched successfully".to_string(),
    })
}

#[get("/users")]
async fn _get_users() -> web::Json<UsersResponse> {
    let mut users = std::collections::HashMap::<i64, String>::new();
    users.insert(1, "Alice".to_string());
    users.insert(2, "Bob".to_string());
    let length = users.len();
    web::Json(UsersResponse { users, length })
}
pub fn role_scope() -> Scope {
    web::scope("/role")
        .service(_get_role_root)
        .service(_get_users)
        .service(_post_role_root)
        .service(_delete_role_root)
        .service(_put_role_root)
        .service(_patch_role_root)
}
