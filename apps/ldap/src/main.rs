use base64::{engine::general_purpose, Engine as _};
use ldap::ldap_service_server::{LdapService, LdapServiceServer};
use ldap::{
    AuthRequest, AuthResponse, Empty, GenericResponse, GroupDetailResponse, GroupRequest,
    ModifyUserRequest, ToggleUserStatusRequest, UserDetailResponse, UserGroupRequest,
    UserIdRequest, UserListResponse, UserRequest,
};
use ldap3::{result::Result as LdapResult, Ldap, LdapConnAsync, Mod, Scope, SearchEntry};
use rand::{rngs::OsRng, RngCore};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

pub mod ldap {
    include!("generated/ldap.rs");
}

#[derive(Debug, Error)]
pub enum LdapServiceError {
    #[error("LDAP connection error: {0}")]
    ConnectionError(String),

    #[error("LDAP operation error: {0}")]
    OperationError(String),

    #[error("User '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("User '{0}' not found")]
    UserNotFound(String),

    #[error("Group '{0}' already exists")]
    GroupAlreadyExists(String),

    #[error("Group '{0}' not found")]
    GroupNotFound(String),

    #[error("Invalid credentials")]
    InvalidCredentials,
}

impl From<LdapServiceError> for Status {
    fn from(err: LdapServiceError) -> Self {
        match err {
            LdapServiceError::ConnectionError(e) => Status::internal(e),
            LdapServiceError::OperationError(e) => Status::internal(e),
            LdapServiceError::UserAlreadyExists(uid) => Status::already_exists(uid),
            LdapServiceError::UserNotFound(uid) => Status::not_found(uid),
            LdapServiceError::GroupAlreadyExists(name) => Status::already_exists(name),
            LdapServiceError::GroupNotFound(name) => Status::not_found(name),
            LdapServiceError::InvalidCredentials => Status::unauthenticated("Invalid credentials"),
        }
    }
}

async fn bind() -> LdapResult<Ldap> {
    let url = "ldap://192.168.56.2:389";
    let (conn, mut ldap) = LdapConnAsync::new(url).await?;
    ldap3::drive!(conn);
    ldap.simple_bind("cn=admin,dc=example,dc=com", "admin")
        .await?
        .success()?;
    Ok(ldap)
}

fn generate_id_from_uuid() -> String {
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let id = u64::from_be_bytes(buf);
    id.to_string()
}

fn hash_password_ssha(password: &str) -> String {
    let mut salt = [0u8; 8];
    let mut rng = OsRng::default();
    rng.fill_bytes(&mut salt);

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt);
    let digest = hasher.finalize();

    let mut ssha = Vec::new();
    ssha.extend_from_slice(&digest);
    ssha.extend_from_slice(&salt);

    format!("{{SSHA256}}{}", general_purpose::STANDARD.encode(&ssha))
}

// ============================================================
// ======================= gRPC Service =======================
// ============================================================

#[derive(Debug, Default)]
pub struct MyLdapService;

#[tonic::async_trait]
impl LdapService for MyLdapService {
    /* ---------------- User APIs ---------------- */
    async fn add_user(
        &self,
        request: Request<UserRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();

        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let dn = format!("uid={},ou=Users,dc=example,dc=com", req.uid);

        let filter = format!("(uid={})", req.uid);
        let base_dn = format!("ou=Users,dc=example,dc=com");
        let (results, _) = ldap
            .search(&base_dn, Scope::OneLevel, &filter, vec!["dn"])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;
        if !results.is_empty() {
            return Err(LdapServiceError::UserAlreadyExists(req.uid.clone()).into());
        }

        let mut attrs = HashMap::new();
        let uid_number = generate_id_from_uuid();
        let hashed_password = hash_password_ssha(&req.user_password);
        attrs.insert(
            "objectClass",
            vec!["inetOrgPerson", "posixAccount", "shadowAccount", "top"],
        );
        attrs.insert("uid", vec![req.uid.as_str()]);
        attrs.insert("userPassword", vec![hashed_password.as_str()]);
        attrs.insert("cn", vec![req.cn.as_str()]);
        attrs.insert("sn", vec![req.sn.as_str()]);
        attrs.insert("homeDirectory", vec![req.home_directory.as_str()]);
        attrs.insert("loginShell", vec![req.login_shell.as_str()]);
        attrs.insert("givenName", vec![req.given_name.as_str()]);
        attrs.insert("displayName", vec![req.display_name.as_str()]);
        attrs.insert("uidNumber", vec![uid_number.as_str()]);
        attrs.insert("gidNumber", vec![req.gid_number.as_str()]);
        attrs.insert("gecos", vec![req.gecos.as_str()]);

        let attributes: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        ldap.add(&dn, attributes)
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("User '{}' added.", req.uid),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<UserIdRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let dn = format!("uid={},ou=Users,dc=example,dc=com", req.uid);

        ldap.delete(&dn)
            .await
            .map_err(|e| match e {
                e if e.to_string().contains("No such object") => {
                    LdapServiceError::UserNotFound(req.uid.clone())
                }
                other => {
                    LdapServiceError::OperationError(format!("LDAP delete error: {:?}", other))
                }
            })?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("User '{}' deleted.", req.uid),
        }))
    }

    async fn modify_user(
        &self,
        request: Request<ModifyUserRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        let dn = format!("uid={},ou=Users,dc=example,dc=com", req.uid);
        let changes: Vec<Mod<String>> = req
            .changes
            .into_iter()
            .map(|(k, v)| {
                let value = if k == "userPassword" {
                    hash_password_ssha(&v)
                } else {
                    v
                };
                Mod::Replace(k, vec![value].into_iter().collect())
            })
            .collect();

        ldap.modify(&dn, changes)
            .await
            .map_err(|e| match e {
                e if e.to_string().contains("No such object") => {
                    LdapServiceError::UserNotFound(req.uid.clone())
                }
                other => LdapServiceError::OperationError(format!("{:?}", other)),
            })?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("User '{}' modified.", req.uid),
        }))
    }

    async fn list_user(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<UserListResponse>, Status> {
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let base_dn = "ou=Users,dc=example,dc=com";

        let (results, _) = ldap
            .search(
                base_dn,
                Scope::OneLevel,
                "(objectClass=inetOrgPerson)",
                vec!["uid"],
            )
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        let users: Vec<String> = results
            .into_iter()
            .filter_map(|entry| {
                let entry = SearchEntry::construct(entry);
                entry.attrs.get("uid").and_then(|v| v.get(0)).cloned()
            })
            .collect();

        Ok(Response::new(UserListResponse { users }))
    }

    async fn search_user(
        &self,
        request: Request<UserIdRequest>,
    ) -> Result<Response<UserDetailResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let filter = format!("(uid={})", req.uid);

        let (results, _) = ldap
            .search(
                "ou=Users,dc=example,dc=com",
                Scope::OneLevel,
                &filter,
                vec!["*"],
            )
            .await
            .map_err(|e| match e {
                e if e.to_string().contains("No such object") => {
                    LdapServiceError::UserNotFound(req.uid.clone())
                }
                other => LdapServiceError::OperationError(format!("{:?}", other)),
            })?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        if results.is_empty() {
            return Ok(Response::new(UserDetailResponse {
                details: format!("User '{}' not found.", req.uid),
            }));
        }

        let entry = SearchEntry::construct(results[0].clone());
        let attrs = &entry.attrs;
        let json_map = serde_json::json!({
            "uid": attrs.get("uid").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "cn": attrs.get("cn").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "sn": attrs.get("sn").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "uidNumber": attrs.get("uidNumber").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "gidNumber": attrs.get("gidNumber").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "homeDirectory": attrs.get("homeDirectory").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "loginShell": attrs.get("loginShell").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "givenName": attrs.get("givenName").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "displayName": attrs.get("displayName").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "gecos": attrs.get("gecos").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
        });

        Ok(Response::new(UserDetailResponse {
            details: json_map.to_string(),
        }))
    }

    async fn authenticate_user(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        let filter = format!("(uid={})", req.uid);
        let (results, _) = ldap
            .search("dc=example,dc=com", Scope::Subtree, &filter, vec!["dn"])
            .await
            .map_err(|e| match e {
                e if e.to_string().contains("No such object") => {
                    LdapServiceError::UserNotFound(req.uid.clone())
                }
                other => LdapServiceError::OperationError(format!("{:?}", other)),
            })?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        if results.is_empty() {
            return Ok(Response::new(AuthResponse {
                success: false,
                message: "User not found".into(),
            }));
        }

        let entry = SearchEntry::construct(results.into_iter().next().unwrap());
        let auth_ok = ldap
            .simple_bind(&entry.dn, &req.user_password)
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .is_ok();

        if auth_ok {
            Ok(Response::new(AuthResponse {
                success: true,
                message: "Authenticated".into(),
            }))
        } else {
            Ok(Response::new(AuthResponse {
                success: false,
                message: "Invalid credentials".into(),
            }))
        }
    }

    async fn toggle_user_status(
        &self,
        request: Request<ToggleUserStatusRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        let dn = format!("uid={},ou=Users,dc=example,dc=com", req.uid);

        let mod_op = if req.enable {
            Mod::Delete("shadowExpire".into(), HashSet::<&str>::new())
        } else {
            Mod::Replace("shadowExpire".into(), vec!["1"].into_iter().collect())
        };

        ldap.modify(&dn, vec![mod_op])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        let msg = if req.enable {
            format!("User '{}' has been enabled.", req.uid)
        } else {
            format!("User '{}' has been disabled.", req.uid)
        };

        Ok(Response::new(GenericResponse { message: msg }))
    }

    /* ---------------- Group APIs ---------------- */
    async fn add_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);

        let filter = format!("(cn={})", req.group_name);
        let (results, _) = ldap
            .search(
                "ou=Groups,dc=example,dc=com",
                Scope::OneLevel,
                &filter,
                vec!["dn"],
            )
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;
        if !results.is_empty() {
            return Err(LdapServiceError::GroupAlreadyExists(req.group_name.clone()).into());
        }

        let mut attrs = HashMap::new();
        let gid_number = generate_id_from_uuid();
        attrs.insert("objectClass", vec!["posixGroup", "top"]);
        attrs.insert("cn", vec![req.group_name.as_str()]);
        attrs.insert("gidNumber", vec![gid_number.as_str()]);

        let attributes: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        ldap.add(&dn, attributes)
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("Group '{}' added.", req.group_name),
        }))
    }

    async fn delete_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);

        ldap.delete(&dn)
            .await
            .map_err(|e| match e {
                e if e.to_string().contains("No such object") => {
                    LdapServiceError::GroupNotFound(req.group_name.clone())
                }
                other => LdapServiceError::OperationError(format!("{:?}", other)),
            })?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("Group '{}' deleted.", req.group_name),
        }))
    }

    async fn list_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GroupDetailResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        if req.group_name.is_empty() {
            let (results, _) = ldap
                .search(
                    "ou=Groups,dc=example,dc=com",
                    Scope::OneLevel,
                    "(objectClass=posixGroup)",
                    vec!["cn"],
                )
                .await
                .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
                .success()
                .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;
            let groups: Vec<String> = results
                .into_iter()
                .filter_map(|e| {
                    let entry = SearchEntry::construct(e);
                    entry.attrs.get("cn").and_then(|v| v.get(0)).cloned()
                })
                .collect();
            return Ok(Response::new(GroupDetailResponse {
                details: groups.join(", "),
            }));
        }

        let base_dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let (results, _) = ldap
            .search(&base_dn, Scope::Base, "(objectClass=posixGroup)", vec!["*"])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;
        if results.is_empty() {
            return Ok(Response::new(GroupDetailResponse {
                details: format!("Group '{}' not found.", req.group_name),
            }));
        }
        let entry = SearchEntry::construct(results[0].clone());
        let attrs = &entry.attrs;
        let json_map = serde_json::json!({
            "cn": attrs.get("cn").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "gidNumber": attrs.get("gidNumber").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            "memberUid": attrs.get("memberUid").cloned().unwrap_or_default(), // 這是 Vec<String>
        });

        Ok(Response::new(GroupDetailResponse {
            details: json_map.to_string(),
        }))
    }

    async fn search_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GroupDetailResponse>, Status> {
        self.list_group(request).await
    }

    async fn add_user_to_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        let base_dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let filter = format!("(memberUid={})", req.uid);

        let (results, _) = ldap
            .search(&base_dn, Scope::Base, &filter, vec!["memberUid"])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        if !results.is_empty() {
            return Err(LdapServiceError::OperationError(format!(
                "User '{}' is already a member of group '{}'",
                req.uid, req.group_name
            ))
            .into());
        }

        let dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let mod_op = Mod::Add(
            "memberUid".into(),
            vec![req.uid.clone()].into_iter().collect(),
        );
        ldap.modify(&dn, vec![mod_op])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!("User '{}' added to group '{}'.", req.uid, req.group_name),
        }))
    }

    async fn remove_user_from_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;

        let base_dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let filter = format!("(memberUid={})", req.uid);

        let (results, _) = ldap
            .search(&base_dn, Scope::Base, &filter, vec!["memberUid"])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("Search failed: {:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("Search failed: {:?}", e)))?;

        if results.is_empty() {
            return Err(LdapServiceError::OperationError(format!(
                "User '{}' is not a member of group '{}'",
                req.uid, req.group_name
            ))
            .into());
        }

        let dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let mod_op = Mod::Delete(
            "memberUid".into(),
            vec![req.uid.clone()].into_iter().collect(),
        );
        ldap.modify(&dn, vec![mod_op])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        Ok(Response::new(GenericResponse {
            message: format!(
                "User '{}' removed from group '{}'.",
                req.uid, req.group_name
            ),
        }))
    }

    async fn list_user_in_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<UserListResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let base_dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);

        let (results, _) = ldap
            .search(
                &base_dn,
                Scope::Base,
                "(objectClass=posixGroup)",
                vec!["memberUid"],
            )
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;
        if results.is_empty() {
            return Ok(Response::new(UserListResponse { users: vec![] }));
        }
        let entry = SearchEntry::construct(results[0].clone());
        let users = entry
            .attrs
            .get("memberUid")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        Ok(Response::new(UserListResponse { users }))
    }

    async fn search_user_in_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let mut ldap = bind()
            .await
            .map_err(|e| LdapServiceError::ConnectionError(format!("{:?}", e)))?;
        let base_dn = format!("cn={},ou=Groups,dc=example,dc=com", req.group_name);
        let filter = format!("(memberUid={})", req.uid);

        let (results, _) = ldap
            .search(&base_dn, Scope::Base, &filter, vec!["memberUid"])
            .await
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?
            .success()
            .map_err(|e| LdapServiceError::OperationError(format!("{:?}", e)))?;

        let found = !results.is_empty();
        Ok(Response::new(GenericResponse {
            message: if found {
                format!("User '{}' is in group '{}'.", req.uid, req.group_name)
            } else {
                format!("User '{}' is NOT in group '{}'.", req.uid, req.group_name)
            },
        }))
    }
}

// ==============================================================
// ============================ Main ============================
// ==============================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let server = MyLdapService::default();

    println!("gRPC server running on {}", addr);

    Server::builder()
        .add_service(LdapServiceServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}