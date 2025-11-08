mod translate;
mod types;
use std::collections::HashMap;

use crate::{
    commons::{ResponseResult, ResponseType},
    handles::chm::role::types::{
        RoleDeleteRequest, RoleInfo, RolePatchRequest, RolePutResponse, RolesResponse,
        UsersResponse,
    },
};
use actix_web::{delete, get, patch, post, put, web, Scope};
use chm_grpc::{
    restful::{
        CreateRoleRequest as Grpc_CreateRoleRequest,
        GetRoleUsersRequest as Grpc_GetRoleUsersRequest, GetRolesRequest as Grpc_GetRolesRequest,
    },
    tonic,
};

// #[get("")]
// async fn _get_role_root() -> web::Json<RolesResponse> {
//     let members = vec![1, 2, 3, 4];
//     let member_length = members.len();
//     let roles = vec![RoleInfo {
//         name: "TEST".to_string(),
//         permissions: 1 << 1,
//         color: Color::Red,
//         members,
//         length: member_length,
//     }];
//     let length = roles.len();
//     web::Json(RolesResponse { roles, length })
// }
#[get("")]
async fn _get_role_root(
    app_state: web::Data<crate::AppState>,
) -> actix_web::Result<web::Json<RolesResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_roles(Grpc_GetRolesRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    let roles = resp
        .roles
        .into_iter()
        .map(|r| RoleInfo {
            name:        r.role_name,
            permissions: r.permissions,
            color:       r.color.map(|c| c.into()).unwrap_or_default(),
            members:     r.members,
            length:      r.length as usize,
        })
        .collect::<Vec<RoleInfo>>();
    let length = usize::try_from(resp.length)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(RolesResponse { roles, length }))
}

#[post("")]
// async fn _post_role_root(data: web::Json<RoleInfo>) ->
// web::Json<ResponseResult> {     println!("Received role data: {data:#?}");
//     web::Json(ResponseResult {
//         r#type:  ResponseType::Ok,
//         message: "Role created successfully".to_string(),
//     })
// }
async fn _post_role_root(
    app_state: web::Data<crate::AppState>,
    data: web::Json<RoleInfo>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let role_info = data.into_inner();
    let grpc_req = Grpc_CreateRoleRequest {
        role_name:   role_info.name,
        permissions: role_info.permissions,
        color:       Some(role_info.color.into()),
        members:     role_info.members,
    };
    let resp = client
        .create_role(grpc_req)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    if let Some(result) = resp.result {
        Ok(web::Json(result.into()))
    } else {
        Err(actix_web::error::ErrorInternalServerError("No result returned from gRPC".to_string()))
    }
}

// #[delete("")]
// async fn _delete_role_root(data: web::Json<RoleDeleteRequest>) ->
// web::Json<ResponseResult> {     dbg!(&data);
//     web::Json(ResponseResult {
//         r#type:  ResponseType::Ok,
//         message: format!("Role '{}' deleted successfully", data.name),
//     })
// }
#[delete("")]
async fn _delete_role_root(
    app_state: web::Data<crate::AppState>,
    data: web::Json<RoleDeleteRequest>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let role_name = data.name.clone();
    let grpc_req = chm_grpc::restful::DeleteRoleRequest { role_name };
    let resp = client
        .delete_role(grpc_req)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    if let Some(result) = resp.result {
        Ok(web::Json(result.into()))
    } else {
        Err(actix_web::error::ErrorInternalServerError("No result returned from gRPC".to_string()))
    }
}

// #[put("")]
// async fn _put_role_root(data: web::Json<RolePutResponse>) ->
// web::Json<ResponseResult> {     dbg!(&data);
//     web::Json(ResponseResult {
//         r#type:  ResponseType::Ok,
//         message: "Role updated successfully".to_string(),
//     })
// }
#[put("")]
async fn _put_role_root(
    app_state: web::Data<crate::AppState>,
    data: web::Json<RolePutResponse>,
) -> actix_web::Result<web::Json<ResponseResult>> {
    let mut client = app_state.gclient.clone();
    let role_info = data.into_inner();
    let grpc_req = chm_grpc::restful::PutRoleMembersRequest {
        role_name: role_info.name,
        members:   role_info.members,
    };
    let resp = client
        .put_role_members(grpc_req)
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    if let Some(result) = resp.result {
        Ok(web::Json(result.into()))
    } else {
        Err(actix_web::error::ErrorInternalServerError("No result returned from gRPC".to_string()))
    }
}

#[patch("")]
async fn _patch_role_root(data: web::Json<RolePatchRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Role patched successfully".to_string(),
    })
}

// #[get("/users")]
// async fn _get_users() -> web::Json<UsersResponse> {
//     let mut users = std::collections::HashMap::<i64, String>::new();
//     users.insert(1, "Alice".to_string());
//     users.insert(2, "Bob".to_string());
//     let length = users.len();
//     web::Json(UsersResponse { users, length })
// }
#[get("/users")]
async fn _get_users(
    app_state: web::Data<crate::AppState>,
) -> actix_web::Result<web::Json<UsersResponse>> {
    let mut client = app_state.gclient.clone();
    let resp = client
        .get_role_users(Grpc_GetRoleUsersRequest {})
        .await
        .map_err(|status| match status.code() {
            tonic::Code::Cancelled | tonic::Code::Unavailable => {
                actix_web::error::ErrorBadGateway(format!("gRPC connection lost: {status}"))
            }
            _ => actix_web::error::ErrorInternalServerError(format!("gRPC call failed: {status}")),
        })?
        .into_inner();
    let users = resp.users.into_iter().collect::<HashMap<String, String>>();
    let length = usize::try_from(resp.length)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    Ok(web::Json(UsersResponse { users, length }))
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
