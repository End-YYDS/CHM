#![allow(dead_code, unused_variables)]

use crate::communication::GrpcClients;
use chm_cert_utils::CertUtils;
use chm_grpc::{
    common::{ResponseResult, ResponseType},
    restful::{restful_service_server::RestfulService, *},
    tonic,
    tonic::{Request, Response, Status},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

// TODO: 由RestFul Server 為Client 調用Controller RestFul gRPC介面
#[derive(Debug)]
pub struct ControllerRestfulServer {
    pub grpc_clients: Arc<GrpcClients>,
}

#[tonic::async_trait]
impl RestfulService for ControllerRestfulServer {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| "CA client not initialized")
            .map_err(|e| Status::internal(e.to_string()))?;
        let req = request.into_inner();
        let res = ldap
            .authenticate_user(req.username.clone(), req.password)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !res {
            Err(Status::permission_denied(format!("Invalid credentials for user {}", req.username)))
        } else {
            let resp = LoginResponse {
                result: Some(ResponseResult {
                    r#type:  ResponseType::Ok as i32,
                    message: "Login successful".to_string(),
                }),
            };
            Ok(Response::new(resp))
        }
    }

    async fn get_all_info(
        &self,
        request: Request<GetAllInfoRequest>,
    ) -> Result<Response<GetAllInfoResponse>, Status> {
        todo!()
    }

    async fn get_info(
        &self,
        request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        todo!()
    }

    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        todo!()
    }

    async fn backup_now(
        &self,
        request: Request<BackupNowRequest>,
    ) -> Result<Response<BackupNowResponse>, Status> {
        todo!()
    }

    async fn get_backups(
        &self,
        request: Request<GetBackupsRequest>,
    ) -> Result<Response<GetBackupsResponse>, Status> {
        todo!()
    }

    async fn reduce_backup(
        &self,
        request: Request<ReductionRequest>,
    ) -> Result<Response<ReductionResponse>, Status> {
        todo!()
    }

    async fn get_valid_certs(
        &self,
        request: Request<GetValidCertsRequest>,
    ) -> Result<Response<GetValidCertsResponse>, Status> {
        let ca = self
            .grpc_clients
            .ca()
            .ok_or_else(|| "CA client not initialized")
            .map_err(|e| Status::internal(e.to_string()))?;
        let r = ca
            .get_all_certificates()
            .await
            .map_err(|e| Status::internal(format!("Failed to get valid certificates: {e}")))?;
        let vaild_certs: Vec<ValidCert> = r
            .iter()
            .map(|cert| ValidCert {
                name:   cert.subject_cn.clone(),
                signer: cert.issuer.clone(),
                period: cert.expiration.as_ref().map(CertUtils::ts_to_string).unwrap_or_default(),
            })
            .collect();
        let length = vaild_certs.len() as u64;
        let ret = GetValidCertsResponse { valid: vaild_certs, length };
        Ok(Response::new(ret))
    }

    async fn get_revoked_certs(
        &self,
        request: Request<GetRevokedCertsRequest>,
    ) -> Result<Response<GetRevokedCertsResponse>, Status> {
        let ca = self
            .grpc_clients
            .ca()
            .ok_or_else(|| "CA client not initialized")
            .map_err(|e| Status::internal(e.to_string()))?;
        let r = ca
            .get_all_revoked_certificates()
            .await
            .map_err(|e| Status::internal(format!("Failed to get revoked certificates: {e}")))?;
        let revoked_certs: Vec<RevokedCert> = r
            .iter()
            .map(|entry| RevokedCert {
                number: entry.cert_serial.clone(),
                time:   entry.revoked_at.as_ref().map(CertUtils::ts_to_string).unwrap_or_default(),
                reason: entry.reason.clone(),
            })
            .collect();
        let length = revoked_certs.len() as u64;
        let ret = GetRevokedCertsResponse { revoke: revoked_certs, length };
        Ok(Response::new(ret))
    }

    async fn revoke_cert(
        &self,
        request: Request<RevokeCertRequest>,
    ) -> Result<Response<RevokeCertResponse>, Status> {
        let RevokeCertRequest { name, reason } = request.into_inner();
        let ca = self
            .grpc_clients
            .ca()
            .ok_or_else(|| "CA client not initialized")
            .map_err(|e| Status::internal(e.to_string()))?;
        let cert = ca
            .get_certificate_by_common_name(&name)
            .await
            .map_err(|e| Status::internal(format!("Failed to get serail {name}")))?;
        let cert = match cert {
            Some(c) => c,
            None => return Err(Status::not_found(format!("Certificate {name} not found"))),
        };
        ca.mark_certificate_as_revoked(cert.serial, Some(reason))
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke certificate {name}: {e}")))?;
        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: format!("憑證 {name} 已成功註銷"),
        };
        let resp = RevokeCertResponse { result: Some(result) };
        Ok(Response::new(resp))
    }

    async fn add_pc(
        &self,
        request: Request<AddPcRequest>,
    ) -> Result<Response<AddPcResponse>, Status> {
        todo!()
    }

    async fn get_all_pcs(
        &self,
        request: Request<GetAllPcsRequest>,
    ) -> Result<Response<GetAllPcsResponse>, Status> {
        todo!()
    }

    async fn get_specific_pcs(
        &self,
        request: Request<GetSpecificPcsRequest>,
    ) -> Result<Response<GetSpecificPcsResponse>, Status> {
        todo!()
    }

    async fn delete_pcs(
        &self,
        request: Request<DeletePcsRequest>,
    ) -> Result<Response<DeletePcsResponse>, Status> {
        todo!()
    }

    async fn reboot_pcs(
        &self,
        request: Request<RebootPcsRequest>,
    ) -> Result<Response<RebootPcsResponse>, Status> {
        todo!()
    }

    async fn shutdown_pcs(
        &self,
        request: Request<ShutdownPcsRequest>,
    ) -> Result<Response<ShutdownPcsResponse>, Status> {
        todo!()
    }

    async fn get_pc_groups(
        &self,
        request: Request<GetPcGroupsRequest>,
    ) -> Result<Response<GetPcGroupsResponse>, Status> {
        todo!()
    }

    async fn create_pc_group(
        &self,
        request: Request<CreatePcGroupRequest>,
    ) -> Result<Response<CreatePcGroupResponse>, Status> {
        todo!()
    }

    async fn put_pc_group(
        &self,
        request: Request<PutPcGroupRequest>,
    ) -> Result<Response<PutPcGroupResponse>, Status> {
        todo!()
    }

    async fn patch_pc_group(
        &self,
        request: Request<PatchPcGroupRequest>,
    ) -> Result<Response<PatchPcGroupResponse>, Status> {
        todo!()
    }

    async fn delete_pc_group(
        &self,
        request: Request<DeletePcGroupRequest>,
    ) -> Result<Response<DeletePcGroupResponse>, Status> {
        todo!()
    }

    async fn get_roles(
        &self,
        request: Request<GetRolesRequest>,
    ) -> Result<Response<GetRolesResponse>, Status> {
        todo!()
    }

    async fn get_role_users(
        &self,
        request: Request<GetRoleUsersRequest>,
    ) -> Result<Response<GetRoleUsersResponse>, Status> {
        todo!()
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        todo!()
    }

    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        todo!()
    }

    async fn put_role_members(
        &self,
        request: Request<PutRoleMembersRequest>,
    ) -> Result<Response<PutRoleMembersResponse>, Status> {
        todo!()
    }

    async fn patch_role(
        &self,
        request: Request<PatchRoleRequest>,
    ) -> Result<Response<PatchRoleResponse>, Status> {
        todo!()
    }

    async fn get_modules(
        &self,
        request: Request<GetModulesRequest>,
    ) -> Result<Response<GetModulesResponse>, Status> {
        todo!()
    }

    async fn upload_modules(
        &self,
        request: Request<UploadModulesRequest>,
    ) -> Result<Response<UploadModulesResponse>, Status> {
        todo!()
    }

    async fn update_modules(
        &self,
        request: Request<UpdateModulesRequest>,
    ) -> Result<Response<UpdateModulesResponse>, Status> {
        todo!()
    }

    async fn patch_module_settings(
        &self,
        request: Request<PatchModuleSettingsRequest>,
    ) -> Result<Response<PatchModuleSettingsResponse>, Status> {
        todo!()
    }

    async fn delete_modules(
        &self,
        request: Request<DeleteModulesRequest>,
    ) -> Result<Response<DeleteModulesResponse>, Status> {
        todo!()
    }

    async fn enable_modules(
        &self,
        request: Request<EnableModulesRequest>,
    ) -> Result<Response<EnableModulesResponse>, Status> {
        todo!()
    }

    async fn disable_modules(
        &self,
        request: Request<DisableModulesRequest>,
    ) -> Result<Response<DisableModulesResponse>, Status> {
        todo!()
    }

    async fn get_ip_access(
        &self,
        request: Request<GetIpAccessRequest>,
    ) -> Result<Response<GetIpAccessResponse>, Status> {
        todo!()
    }

    async fn post_ip(
        &self,
        request: Request<PostIpRequest>,
    ) -> Result<Response<PostIpResponse>, Status> {
        todo!()
    }

    async fn delete_ip(
        &self,
        request: Request<DeleteIpRequest>,
    ) -> Result<Response<DeleteIpResponse>, Status> {
        todo!()
    }

    async fn put_ip_mode(
        &self,
        request: Request<PutIpModeRequest>,
    ) -> Result<Response<PutIpModeResponse>, Status> {
        todo!()
    }

    async fn get_setting_values(
        &self,
        request: Request<GetSettingValuesRequest>,
    ) -> Result<Response<GetSettingValuesResponse>, Status> {
        todo!()
    }

    async fn put_setting_values(
        &self,
        request: Request<PutSettingValuesRequest>,
    ) -> Result<Response<PutSettingValuesResponse>, Status> {
        todo!()
    }

    async fn get_users(
        &self,
        request: Request<GetUsersRequest>,
    ) -> Result<Response<GetUsersResponse>, Status> {
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))
            .map_err(|e| Status::internal(e.to_string()))?;
        let uids = ldap
            .list_users()
            .await
            .map_err(|e| Status::internal(format!("Failed to list users: {e}")))?;
        let mut users: HashMap<String, UserEntry> = HashMap::new();
        for uid in uids {
            match ldap.search_user(uid.clone()).await {
                Ok(detail) => {
                    let gid_number = detail.gid_number.clone();
                    let group_name = ldap
                        .get_group_name(gid_number)
                        .await
                        .map_err(|e| Status::not_found(e.to_string()))?
                        .group_name;
                    let entry = UserEntry {
                        username:       detail.uid,
                        password:       "".to_string(),
                        cn:             detail.cn,
                        sn:             detail.sn,
                        home_directory: detail.home_directory,
                        shell:          detail.login_shell,
                        given_name:     detail.given_name,
                        display_name:   detail.display_name,
                        gid_number:     detail.gid_number,
                        group:          vec![group_name],
                        gecos:          detail.gecos,
                    };
                    users.insert(uid, entry);
                }
                Err(e) => {
                    eprintln!("Failed to fetch details for user {}: {}", uid, e);
                    continue;
                }
            }
        }
        let length = users.len() as u64;
        let resp = GetUsersResponse { users, length };
        Ok(Response::new(resp))
    }

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();
        let user = req.user.ok_or_else(|| Status::invalid_argument("User field is required"))?;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        let username = user.username.clone();
        if !user.group.is_empty() {
            for group_name in user.group.iter() {
                if group_name == &username {
                    continue;
                }
                if let Err(e) = ldap.search_group(group_name.clone()).await {
                    return Err(Status::not_found(format!(
                        "Group {} not found: {}",
                        group_name, e
                    )));
                }
            }
        }
        ldap.add_user(
            username.clone(),
            user.password,
            Some(user.cn),
            Some(user.sn),
            Some(user.home_directory),
            Some(user.shell),
            Some(user.given_name),
            Some(user.display_name),
            Some(user.gid_number),
            Some(user.gecos),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to add user {}: {e}", username)))?;
        for group_name in user.group.iter() {
            if group_name == &username {
                continue;
            }
            ldap.add_user_to_group(username.clone(), group_name.clone()).await.map_err(|e| {
                Status::internal(format!(
                    "Failed to add user {} to group {}: {e}",
                    username, group_name
                ))
            })?;
        }
        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: format!("使用者 {} 已成功建立", username),
        };
        Ok(Response::new(CreateUserResponse { result: Some(result) }))
    }

    async fn put_users(
        &self,
        request: Request<PutUsersRequest>,
    ) -> Result<Response<PutUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        if users.is_empty() {
            return Err(Status::invalid_argument("At least one user entry is required"));
        }
        let (username, user) = users
            .iter()
            .next()
            .ok_or_else(|| Status::invalid_argument("At least one user entry is required"))?;

        if let Err(e) = ldap.search_user(username.clone()).await {
            return Err(Status::not_found(format!("User {} not found: {}", username, e)));
        }
        if !user.group.is_empty() {
            for group_name in user.group.iter() {
                if group_name == username {
                    continue; // 跳過 primary group
                }
                if let Err(e) = ldap.search_group(group_name.clone()).await {
                    return Err(Status::not_found(format!(
                        "Group {} not found: {}",
                        group_name, e
                    )));
                }
            }
        }
        let mut attr: HashMap<String, String> = HashMap::new();
        attr.insert("userPassword".into(), user.password.clone());
        attr.insert("cn".into(), user.cn.clone());
        attr.insert("sn".into(), user.sn.clone());
        attr.insert("homeDirectory".into(), user.home_directory.clone());
        attr.insert("loginShell".into(), user.shell.clone());
        attr.insert("givenName".into(), user.given_name.clone());
        attr.insert("displayName".into(), user.display_name.clone());
        attr.insert("gecos".into(), user.gecos.clone());
        ldap.modify_user(username.clone(), attr)
            .await
            .map_err(|e| Status::internal(format!("Failed to modify user {}: {}", username, e)))?;

        for group_name in user.group.iter() {
            if group_name == username {
                continue;
            }
            ldap.add_user_to_group(username.clone(), group_name.clone()).await.map_err(|e| {
                Status::internal(format!(
                    "Failed to add user {} to group {}: {}",
                    username, group_name, e
                ))
            })?;
        }

        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: format!("使用者 {} 已成功更新", username),
        };

        Ok(Response::new(PutUsersResponse { result: Some(result) }))
    }

    async fn patch_users(
        &self,
        request: Request<PatchUsersRequest>,
    ) -> Result<Response<PatchUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        if users.is_empty() {
            return Err(Status::invalid_argument("At least one user entry is required"));
        }
        let (username, user) = users
            .iter()
            .next()
            .ok_or_else(|| Status::invalid_argument("At least one user entry is required"))?;

        if let Err(e) = ldap.search_user(username.clone()).await {
            return Err(Status::not_found(format!("User {} not found: {}", username, e)));
        }
        let mut attr: HashMap<String, String> = HashMap::new();
        if let Some(u) = &user.password {
            attr.insert("userPassword".into(), u.clone());
        }
        if let Some(u) = &user.cn {
            attr.insert("cn".into(), u.clone());
        }
        if let Some(u) = &user.sn {
            attr.insert("sn".into(), u.clone());
        }
        if let Some(u) = &user.home_directory {
            attr.insert("homeDirectory".into(), u.clone());
        }
        if let Some(u) = &user.shell {
            attr.insert("loginShell".into(), u.clone());
        }
        if let Some(u) = &user.given_name {
            attr.insert("givenName".into(), u.clone());
        }
        if let Some(u) = &user.display_name {
            attr.insert("displayName".into(), u.clone());
        }
        if let Some(u) = &user.gecos {
            attr.insert("gecos".into(), u.clone());
        }
        if !user.group.is_empty() {
            for group_name in user.group.iter() {
                if group_name == username {
                    continue; // 跳過 primary group
                }
                if let Err(e) = ldap.search_group(group_name.clone()).await {
                    return Err(Status::not_found(format!(
                        "Group {} not found: {}",
                        group_name, e
                    )));
                }
            }
        }
        ldap.modify_user(username.clone(), attr)
            .await
            .map_err(|e| Status::internal(format!("Failed to modify user {}: {}", username, e)))?;
        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: format!("使用者 {} 已成功更新", username),
        };
        Ok(Response::new(PatchUsersResponse { result: Some(result) }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();
        let uid = req.uid;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        if let Err(e) = ldap.search_user(uid.clone()).await {
            return Err(Status::not_found(format!("User {} not found: {}", uid, e)));
        }
        ldap.delete_user(uid.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to delete user {}: {}", uid, e)))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("使用者 {} 已成功刪除", uid),
        };
        Ok(Response::new(DeleteUserResponse { result: Some(result) }))
    }

    async fn get_groups(
        &self,
        request: Request<GetGroupsRequest>,
    ) -> Result<Response<GetGroupsResponse>, Status> {
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))
            .map_err(|e| Status::internal(e.to_string()))?;
        let gids = ldap
            .list_groups()
            .await
            .map_err(|e| Status::internal(format!("Failed to list groups: {e}")))?;
        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        for gid in gids {
            match ldap.search_group(gid.clone()).await {
                Ok(detail) => {
                    let entry = GroupInfo { groupname: detail.cn, users: detail.member_uid };
                    groups.insert(gid, entry);
                }
                Err(e) => {
                    eprintln!("Failed to fetch details for group {}: {}", gid, e);
                    continue;
                }
            }
        }
        let resp = GetGroupsResponse { groups };
        Ok(Response::new(resp))
    }

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let req = request.into_inner();
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        let groupname = req.groupname.clone();
        let users = req.users.clone();
        ldap.add_group(groupname.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to add group {}: {}", groupname, e)))?;
        for uid in users {
            ldap.add_user_to_group(uid.clone(), groupname.clone()).await.map_err(|e| {
                Status::internal(format!(
                    "Failed to add user {} to group {}: {}",
                    uid, groupname, e
                ))
            })?;
        }
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("群組 {} 已成功建立", req.groupname),
        };
        Ok(Response::new(CreateGroupResponse { result: Some(result) }))
    }

    async fn put_groups(
        &self,
        request: Request<PutGroupsRequest>,
    ) -> Result<Response<PutGroupsResponse>, Status> {
        let req = request.into_inner();
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        for (old_name, group_info) in req.groups.iter() {
            let new_name = &group_info.groupname;

            let group_exists = ldap
                .search_group(new_name.clone())
                .await
                .map(|_| true)
                .or_else(|_| Ok(false))
                .map_err(|e: Box<dyn std::error::Error + Send + Sync>| {
                    Status::internal(format!("LDAP search error: {}", e))
                })?;
            if old_name != new_name {
                ldap.modify_group_name(old_name.clone(), new_name.clone()).await.map_err(|e| {
                    Status::internal(format!(
                        "Failed to rename group {} -> {}: {}",
                        old_name, new_name, e
                    ))
                })?;
            }
            let current_users: Vec<String> =
                ldap.list_user_in_group(new_name.clone()).await.map_err(|e| {
                    Status::internal(format!("Failed to list users in group {}: {}", new_name, e))
                })?;
            let new_users: HashSet<_> = group_info.users.iter().cloned().collect();
            let current_users_set: HashSet<_> = current_users.into_iter().collect();
            for uid in new_users.difference(&current_users_set) {
                ldap.search_user(uid.clone())
                    .await
                    .map_err(|e| Status::not_found(format!("User {} not found: {}", uid, e)))?;
                ldap.add_user_to_group(uid.clone(), new_name.clone()).await.map_err(|e| {
                    Status::internal(format!(
                        "Failed to add user {} to group {}: {}",
                        uid, new_name, e
                    ))
                })?;
            }
            for uid in current_users_set.difference(&new_users) {
                ldap.remove_user_from_group(uid.clone(), new_name.clone()).await.map_err(|e| {
                    Status::internal(format!(
                        "Failed to remove user {} from group {}: {}",
                        uid, new_name, e
                    ))
                })?;
            }
        }
        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: "群組資料已成功更新".to_string(),
        };
        Ok(Response::new(PutGroupsResponse { result: Some(result) }))
    }

    async fn patch_groups(
        &self,
        request: Request<PatchGroupsRequest>,
    ) -> Result<Response<PatchGroupsResponse>, Status> {
        let req = request.into_inner();
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        if req.groups.is_empty() {
            return Err(Status::invalid_argument("At least one group entry is required"));
        }
        for (old_name, patch_info) in req.groups.iter() {
            if let Some(new_name) = &patch_info.groupname {
                if old_name != new_name {
                    let group_exists = ldap
                        .search_group(new_name.clone())
                        .await
                        .map(|_| true)
                        .or_else(|_| Ok(false))
                        .map_err(|e: Box<dyn std::error::Error + Send + Sync>| {
                            Status::internal(format!("LDAP search error: {}", e))
                        })?;
                    if group_exists {
                        return Err(Status::already_exists(format!(
                            "Group '{}' already exists",
                            new_name
                        )));
                    }
                    ldap.modify_group_name(old_name.clone(), new_name.clone()).await.map_err(
                        |e| {
                            Status::internal(format!(
                                "Failed to rename group {} -> {}: {}",
                                old_name, new_name, e
                            ))
                        },
                    )?;
                }
            }
            if !patch_info.users.is_empty() {
                let users = &patch_info.users;
                let group_name = patch_info.groupname.as_ref().unwrap_or(old_name);
                let current_users =
                    ldap.list_user_in_group(group_name.clone()).await.map_err(|e| {
                        Status::internal(format!(
                            "Failed to list users in group {}: {}",
                            group_name, e
                        ))
                    })?;
                let current_set: HashSet<_> = current_users.into_iter().collect();
                let new_set: HashSet<_> = users.iter().cloned().collect();
                for uid in new_set.difference(&current_set) {
                    ldap.add_user_to_group(uid.clone(), group_name.clone()).await.map_err(|e| {
                        Status::internal(format!("Failed to add user {}: {}", uid, e))
                    })?;
                }
                for uid in current_set.difference(&new_set) {
                    ldap.remove_user_from_group(uid.clone(), group_name.clone()).await.map_err(
                        |e| Status::internal(format!("Failed to remove user {}: {}", uid, e)),
                    )?;
                }
            }
        }
        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: "群組已成功更新".to_string(),
        };
        Ok(Response::new(PatchGroupsResponse { result: Some(result) }))
    }

    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let req = request.into_inner();
        let group_name = req.gid;
        let ldap = self
            .grpc_clients
            .ldap()
            .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        if let Err(e) = ldap.search_group(group_name.clone()).await {
            return Err(Status::not_found(format!("Group {} not found: {}", group_name, e)));
        }
        ldap.delete_group(group_name.clone()).await.map_err(|e| {
            Status::internal(format!("Failed to delete group {}: {}", group_name, e))
        })?;

        let result = chm_grpc::common::ResponseResult {
            r#type:  chm_grpc::common::ResponseType::Ok as i32,
            message: format!("群組 {} 已成功刪除", group_name),
        };
        Ok(Response::new(DeleteGroupResponse { result: Some(result) }))
    }

    async fn get_cron_jobs(
        &self,
        request: Request<GetCronJobsRequest>,
    ) -> Result<Response<GetCronJobsResponse>, Status> {
        todo!()
    }

    async fn create_cron(
        &self,
        request: Request<CreateCronRequest>,
    ) -> Result<Response<CreateCronResponse>, Status> {
        todo!()
    }

    async fn delete_cron(
        &self,
        request: Request<DeleteCronRequest>,
    ) -> Result<Response<DeleteCronResponse>, Status> {
        todo!()
    }

    async fn put_cron(
        &self,
        request: Request<PutCronRequest>,
    ) -> Result<Response<PutCronResponse>, Status> {
        todo!()
    }

    async fn import_cron(
        &self,
        request: Request<ImportCronRequest>,
    ) -> Result<Response<ImportCronResponse>, Status> {
        todo!()
    }

    async fn export_cron(
        &self,
        request: Request<ExportCronRequest>,
    ) -> Result<Response<ExportCronResponse>, Status> {
        todo!()
    }

    async fn get_pdir_pcs(
        &self,
        request: Request<GetPdirPcsRequest>,
    ) -> Result<Response<GetPdirPcsResponse>, Status> {
        todo!()
    }

    async fn get_pdir_one(
        &self,
        request: Request<GetPdirOneRequest>,
    ) -> Result<Response<GetPdirOneResponse>, Status> {
        todo!()
    }

    async fn upload_pdir_files(
        &self,
        request: Request<UploadPdirFilesRequest>,
    ) -> Result<Response<UploadPdirFilesResponse>, Status> {
        todo!()
    }

    async fn download_pdir_file(
        &self,
        request: Request<DownloadPdirFileRequest>,
    ) -> Result<Response<DownloadPdirFileResponse>, Status> {
        todo!()
    }

    async fn get_vdir_path(
        &self,
        request: Request<GetVdirPathRequest>,
    ) -> Result<Response<GetVdirPathResponse>, Status> {
        todo!()
    }

    async fn upload_vdir_files(
        &self,
        request: Request<UploadVdirFilesRequest>,
    ) -> Result<Response<UploadVdirFilesResponse>, Status> {
        todo!()
    }

    async fn download_vdir_file(
        &self,
        request: Request<DownloadVdirFileRequest>,
    ) -> Result<Response<DownloadVdirFileResponse>, Status> {
        todo!()
    }

    async fn get_sys_logs(
        &self,
        request: Request<GetSysLogsRequest>,
    ) -> Result<Response<GetSysLogsResponse>, Status> {
        todo!()
    }

    async fn query_sys_logs(
        &self,
        request: Request<QuerySysLogsRequest>,
    ) -> Result<Response<QuerySysLogsResponse>, Status> {
        todo!()
    }

    async fn get_pc_log_pcs(
        &self,
        request: Request<GetPcLogPcsRequest>,
    ) -> Result<Response<GetPcLogPcsResponse>, Status> {
        todo!()
    }

    async fn get_pc_logs(
        &self,
        request: Request<GetPcLogsRequest>,
    ) -> Result<Response<GetPcLogsResponse>, Status> {
        todo!()
    }

    async fn query_pc_logs(
        &self,
        request: Request<QueryPcLogsRequest>,
    ) -> Result<Response<QueryPcLogsResponse>, Status> {
        todo!()
    }

    async fn get_firewall_pcs(
        &self,
        request: Request<GetFirewallPcsRequest>,
    ) -> Result<Response<GetFirewallPcsResponse>, Status> {
        todo!()
    }

    async fn get_firewall(
        &self,
        request: Request<GetFirewallRequest>,
    ) -> Result<Response<GetFirewallResponse>, Status> {
        todo!()
    }

    async fn add_firewall_rule(
        &self,
        request: Request<AddFirewallRuleRequest>,
    ) -> Result<Response<AddFirewallRuleResponse>, Status> {
        todo!()
    }

    async fn delete_firewall_rule(
        &self,
        request: Request<DeleteFirewallRuleRequest>,
    ) -> Result<Response<DeleteFirewallRuleResponse>, Status> {
        todo!()
    }

    async fn put_firewall_status(
        &self,
        request: Request<PutFirewallStatusRequest>,
    ) -> Result<Response<PutFirewallStatusResponse>, Status> {
        todo!()
    }

    async fn put_firewall_policy(
        &self,
        request: Request<PutFirewallPolicyRequest>,
    ) -> Result<Response<PutFirewallPolicyResponse>, Status> {
        todo!()
    }

    async fn get_all_net(
        &self,
        request: Request<GetAllNetRequest>,
    ) -> Result<Response<GetAllNetResponse>, Status> {
        todo!()
    }

    async fn create_net(
        &self,
        request: Request<CreateNetRequest>,
    ) -> Result<Response<CreateNetResponse>, Status> {
        todo!()
    }

    async fn delete_net(
        &self,
        request: Request<DeleteNetRequest>,
    ) -> Result<Response<DeleteNetResponse>, Status> {
        todo!()
    }

    async fn patch_net(
        &self,
        request: Request<PatchNetRequest>,
    ) -> Result<Response<PatchNetResponse>, Status> {
        todo!()
    }

    async fn put_net(
        &self,
        request: Request<PutNetRequest>,
    ) -> Result<Response<PutNetResponse>, Status> {
        todo!()
    }

    async fn net_up(
        &self,
        request: Request<NetUpRequest>,
    ) -> Result<Response<NetUpResponse>, Status> {
        todo!()
    }

    async fn net_down(
        &self,
        request: Request<NetDownRequest>,
    ) -> Result<Response<NetDownResponse>, Status> {
        todo!()
    }

    async fn get_all_route(
        &self,
        request: Request<GetAllRouteRequest>,
    ) -> Result<Response<GetAllRouteResponse>, Status> {
        todo!()
    }

    async fn create_route(
        &self,
        request: Request<CreateRouteRequest>,
    ) -> Result<Response<CreateRouteResponse>, Status> {
        todo!()
    }

    async fn delete_route(
        &self,
        request: Request<DeleteRouteRequest>,
    ) -> Result<Response<DeleteRouteResponse>, Status> {
        todo!()
    }

    async fn patch_route(
        &self,
        request: Request<PatchRouteRequest>,
    ) -> Result<Response<PatchRouteResponse>, Status> {
        todo!()
    }

    async fn put_route(
        &self,
        request: Request<PutRouteRequest>,
    ) -> Result<Response<PutRouteResponse>, Status> {
        todo!()
    }

    async fn get_all_dns(
        &self,
        request: Request<GetAllDnsRequest>,
    ) -> Result<Response<GetAllDnsResponse>, Status> {
        todo!()
    }

    async fn patch_hostname(
        &self,
        request: Request<PatchHostnameRequest>,
    ) -> Result<Response<PatchHostnameResponse>, Status> {
        todo!()
    }

    async fn put_dns(
        &self,
        request: Request<PutDnsRequest>,
    ) -> Result<Response<PutDnsResponse>, Status> {
        todo!()
    }

    async fn get_all_process(
        &self,
        request: Request<GetAllProcessRequest>,
    ) -> Result<Response<GetAllProcessResponse>, Status> {
        todo!()
    }

    async fn get_one_process(
        &self,
        request: Request<GetOneProcessRequest>,
    ) -> Result<Response<GetOneProcessResponse>, Status> {
        todo!()
    }

    async fn start_process(
        &self,
        request: Request<StartProcessRequest>,
    ) -> Result<Response<StartProcessResponse>, Status> {
        todo!()
    }

    async fn stop_process(
        &self,
        request: Request<StopProcessRequest>,
    ) -> Result<Response<StopProcessResponse>, Status> {
        todo!()
    }

    async fn restart_process(
        &self,
        request: Request<RestartProcessRequest>,
    ) -> Result<Response<RestartProcessResponse>, Status> {
        todo!()
    }

    async fn enable_process(
        &self,
        request: Request<EnableProcessRequest>,
    ) -> Result<Response<EnableProcessResponse>, Status> {
        todo!()
    }

    async fn disable_process(
        &self,
        request: Request<DisableProcessRequest>,
    ) -> Result<Response<DisableProcessResponse>, Status> {
        todo!()
    }

    async fn start_enable_process(
        &self,
        request: Request<StartEnableProcessRequest>,
    ) -> Result<Response<StartEnableProcessResponse>, Status> {
        todo!()
    }

    async fn stop_disable_process(
        &self,
        request: Request<StopDisableProcessRequest>,
    ) -> Result<Response<StopDisableProcessResponse>, Status> {
        todo!()
    }

    async fn get_software(
        &self,
        request: Request<GetSoftwareRequest>,
    ) -> Result<Response<GetSoftwareResponse>, Status> {
        todo!()
    }

    async fn install_software(
        &self,
        request: Request<InstallSoftwareRequest>,
    ) -> Result<Response<PackageActionResponse>, Status> {
        todo!()
    }

    async fn delete_software(
        &self,
        request: Request<DeleteSoftwareRequest>,
    ) -> Result<Response<PackageActionResponse>, Status> {
        todo!()
    }

    async fn get_apache_status(
        &self,
        request: Request<GetApacheRequest>,
    ) -> Result<Response<GetApacheResponse>, Status> {
        todo!()
    }

    async fn start_apache(
        &self,
        request: Request<StartApacheRequest>,
    ) -> Result<Response<StartApacheResponse>, Status> {
        todo!()
    }

    async fn stop_apache(
        &self,
        request: Request<StopApacheRequest>,
    ) -> Result<Response<StopApacheResponse>, Status> {
        todo!()
    }

    async fn restart_apache(
        &self,
        request: Request<RestartApacheRequest>,
    ) -> Result<Response<RestartApacheResponse>, Status> {
        todo!()
    }

    async fn get_bind_status(
        &self,
        request: Request<GetBindRequest>,
    ) -> Result<Response<GetBindResponse>, Status> {
        todo!()
    }

    async fn start_bind(
        &self,
        request: Request<StartBindRequest>,
    ) -> Result<Response<StartBindResponse>, Status> {
        todo!()
    }

    async fn stop_bind(
        &self,
        request: Request<StopBindRequest>,
    ) -> Result<Response<StopBindResponse>, Status> {
        todo!()
    }

    async fn restart_bind(
        &self,
        request: Request<RestartBindRequest>,
    ) -> Result<Response<RestartBindResponse>, Status> {
        todo!()
    }

    async fn get_ldap_status(
        &self,
        request: Request<GetLdapRequest>,
    ) -> Result<Response<GetLdapResponse>, Status> {
        todo!()
    }

    async fn start_ldap(
        &self,
        request: Request<StartLdapRequest>,
    ) -> Result<Response<StartLdapResponse>, Status> {
        todo!()
    }

    async fn stop_ldap(
        &self,
        request: Request<StopLdapRequest>,
    ) -> Result<Response<StopLdapResponse>, Status> {
        todo!()
    }

    async fn restart_ldap(
        &self,
        request: Request<RestartLdapRequest>,
    ) -> Result<Response<RestartLdapResponse>, Status> {
        todo!()
    }

    async fn get_my_sql_status(
        &self,
        request: Request<GetMySqlRequest>,
    ) -> Result<Response<GetMySqlResponse>, Status> {
        todo!()
    }

    async fn start_my_sql(
        &self,
        request: Request<StartMySqlRequest>,
    ) -> Result<Response<StartMySqlResponse>, Status> {
        todo!()
    }

    async fn stop_my_sql(
        &self,
        request: Request<StopMySqlRequest>,
    ) -> Result<Response<StopMySqlResponse>, Status> {
        todo!()
    }

    async fn restart_my_sql(
        &self,
        request: Request<RestartMySqlRequest>,
    ) -> Result<Response<RestartMySqlResponse>, Status> {
        todo!()
    }

    async fn get_nginx_status(
        &self,
        request: Request<GetNginxRequest>,
    ) -> Result<Response<GetNginxResponse>, Status> {
        todo!()
    }

    async fn start_nginx(
        &self,
        request: Request<StartNginxRequest>,
    ) -> Result<Response<StartNginxResponse>, Status> {
        todo!()
    }

    async fn stop_nginx(
        &self,
        request: Request<StopNginxRequest>,
    ) -> Result<Response<StopNginxResponse>, Status> {
        todo!()
    }

    async fn restart_nginx(
        &self,
        request: Request<RestartNginxRequest>,
    ) -> Result<Response<RestartNginxResponse>, Status> {
        todo!()
    }

    async fn get_ftp_status(
        &self,
        request: Request<GetFtpRequest>,
    ) -> Result<Response<GetFtpResponse>, Status> {
        todo!()
    }

    async fn start_ftp(
        &self,
        request: Request<StartFtpRequest>,
    ) -> Result<Response<StartFtpResponse>, Status> {
        todo!()
    }

    async fn stop_ftp(
        &self,
        request: Request<StopFtpRequest>,
    ) -> Result<Response<StopFtpResponse>, Status> {
        todo!()
    }

    async fn restart_ftp(
        &self,
        request: Request<RestartFtpRequest>,
    ) -> Result<Response<RestartFtpResponse>, Status> {
        todo!()
    }

    async fn get_samba_status(
        &self,
        request: Request<GetSambaRequest>,
    ) -> Result<Response<GetSambaResponse>, Status> {
        todo!()
    }

    async fn start_samba(
        &self,
        request: Request<StartSambaRequest>,
    ) -> Result<Response<StartSambaResponse>, Status> {
        todo!()
    }

    async fn stop_samba(
        &self,
        request: Request<StopSambaRequest>,
    ) -> Result<Response<StopSambaResponse>, Status> {
        todo!()
    }

    async fn restart_samba(
        &self,
        request: Request<RestartSambaRequest>,
    ) -> Result<Response<RestartSambaResponse>, Status> {
        todo!()
    }

    async fn get_server_installed_pcs(
        &self,
        request: Request<GetServerInstalledPcsRequest>,
    ) -> Result<Response<GetServerInstalledPcsResponse>, Status> {
        todo!()
    }

    async fn get_server_not_installed_pcs(
        &self,
        request: Request<GetServerNotInstalledPcsRequest>,
    ) -> Result<Response<GetServerNotInstalledPcsResponse>, Status> {
        todo!()
    }

    async fn install_server(
        &self,
        request: Request<InstallServerRequest>,
    ) -> Result<Response<InstallServerResponse>, Status> {
        todo!()
    }

    async fn get_squid(
        &self,
        request: Request<GetSquidRequest>,
    ) -> Result<Response<GetSquidResponse>, Status> {
        todo!()
    }

    async fn start_squid(
        &self,
        request: Request<StartSquidRequest>,
    ) -> Result<Response<StartSquidResponse>, Status> {
        todo!()
    }

    async fn stop_squid(
        &self,
        request: Request<StopSquidRequest>,
    ) -> Result<Response<StopSquidResponse>, Status> {
        todo!()
    }

    async fn restart_squid(
        &self,
        request: Request<RestartSquidRequest>,
    ) -> Result<Response<RestartSquidResponse>, Status> {
        todo!()
    }

    async fn get_ssh(
        &self,
        request: Request<GetSshRequest>,
    ) -> Result<Response<GetSshResponse>, Status> {
        todo!()
    }

    async fn start_ssh(
        &self,
        request: Request<StartSshRequest>,
    ) -> Result<Response<StartSshResponse>, Status> {
        todo!()
    }

    async fn stop_ssh(
        &self,
        request: Request<StopSshRequest>,
    ) -> Result<Response<StopSshResponse>, Status> {
        todo!()
    }

    async fn restart_ssh(
        &self,
        request: Request<RestartSshRequest>,
    ) -> Result<Response<RestartSshResponse>, Status> {
        todo!()
    }
}
