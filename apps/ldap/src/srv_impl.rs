use crate::{
    allocator::get_allocator,
    error::{LdapServiceError, SrvResult},
    globals::GlobalConfig,
};
use chm_grpc::ldap::{
    AuthRequest, AuthResponse, GenericResponse, GroupDetailResponse, GroupListResponse,
    GroupRequest, ModifyUserRequest, ToggleUserStatusRequest, UserDetailResponse, UserGroupRequest,
    UserIdRequest, UserListResponse, UserRequest, WebRoleDetailResponse,
};
use ldap3::{Ldap, LdapError, Mod, Scope, SearchEntry};
use std::collections::{HashMap, HashSet};

const RC_NO_SUCH_ATTRIBUTE: u32 = 16;
const RC_NO_SUCH_OBJECT: u32 = 32;

fn base_dn() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.base_dn.clone())
}
fn users_base() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.user_dn.clone())
}
fn groups_base() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.group_dn.clone())
}
fn upg_base() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.upg_dn.clone())
}
fn web_base() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.web_dn.clone())
}
// fn service_base() -> String {
//     GlobalConfig::with(|cfg| cfg.extend.ldap_settings.service_dn.clone())
// }
fn administrators_group() -> String {
    format!("cn=administrators,{}", groups_base())
}
fn upg_dn_of(uid: &str) -> String {
    format!("cn={uid},{}", upg_base())
}

fn hash_password(password: &str) -> String {
    let phc = chm_password::hash_password_phc(password).unwrap();
    format!("{{ARGON2}}{phc}")
}
fn is_shadow_locked(shadow_expire_val: &str) -> bool {
    if shadow_expire_val.trim() == "1" {
        return true;
    }
    false
}

#[inline]
fn err_has_rc(err: &LdapError, want: u32) -> bool {
    if let LdapError::LdapResult { result } = err {
        result.rc == want
    } else {
        false
    }
}

#[inline]
fn is_no_such_attribute(err: &LdapError) -> bool {
    err_has_rc(err, RC_NO_SUCH_ATTRIBUTE)
}

#[inline]
fn is_no_such_object(err: &LdapError) -> bool {
    err_has_rc(err, RC_NO_SUCH_OBJECT)
}

fn map_to_attrs<'a>(mut m: HashMap<&'a str, Vec<&'a str>>) -> Vec<(&'a str, HashSet<&'a str>)> {
    m.drain().map(|(k, v)| (k, v.into_iter().collect::<HashSet<_>>())).collect()
}

async fn search_one(
    ldap: &mut Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
) -> SrvResult<Option<SearchEntry>> {
    let (entries, _) = ldap.search(base, scope, filter, attrs).await?.success()?;
    Ok(entries.into_iter().next().map(SearchEntry::construct))
}
async fn must_find_dn_by_uid(ldap: &mut Ldap, uid: &str) -> SrvResult<String> {
    let ubase = users_base();
    let filter = format!("(uid={uid})");
    if let Some(se) = search_one(ldap, &ubase, Scope::OneLevel, &filter, vec!["dn"]).await? {
        Ok(se.dn)
    } else {
        Err(LdapServiceError::UserNotFound(uid.to_string()))
    }
}
async fn must_find_upg_dn_by_uid(ldap: &mut Ldap, uid: &str) -> SrvResult<String> {
    let filter = format!("(cn={uid})");
    if let Some(se) = search_one(ldap, &upg_base(), Scope::OneLevel, &filter, vec!["dn"]).await? {
        Ok(se.dn)
    } else {
        Err(LdapServiceError::GroupNotFound(format!("UPG '{uid}' not found")))
    }
}

async fn ensure_upg_posix_group(ldap: &mut Ldap, uid: &str, gid_number: i64) -> SrvResult<bool> {
    let g_dn = upg_dn_of(uid);
    let filter = format!("(cn={uid})");
    if let Some(se) =
        search_one(ldap, &upg_base(), Scope::OneLevel, &filter, vec!["dn", "gidNumber"]).await?
    {
        if let Some(vals) = se.attrs.get("gidNumber") {
            if let Some(v) = vals.first() {
                if v.parse::<i64>().ok() == Some(gid_number) {
                    return Ok(false);
                }
            }
        }
        return Err(LdapServiceError::GroupAlreadyExists(format!(
            "UPG '{uid}' already exists with a different gidNumber"
        )));
    }

    let gid_string = gid_number.to_string();
    let mut g_attrs = HashMap::new();
    g_attrs.insert("objectClass", vec!["top", "posixGroup"]);
    g_attrs.insert("cn", vec![uid]);
    g_attrs.insert("gidNumber", vec![&*gid_string]);

    let attributes = map_to_attrs(g_attrs);
    ldap.add(&g_dn, attributes).await?.success()?;
    Ok(true)
}

pub(crate) async fn add_user_impl(ldap: &mut Ldap, req: UserRequest) -> SrvResult<()> {
    let base_dn = base_dn();
    get_allocator().await.reseed_from_ldap(ldap, &base_dn).await?;
    let user_ou = users_base();
    let filter = format!("(uid={})", req.uid);
    if ldap.search(&user_ou, Scope::OneLevel, &filter, vec!["dn"]).await?.success().is_err() {
        return Err(LdapServiceError::OperationError("LDAP search operation failed".into()));
    }
    let uid_number = get_allocator().await.alloc_uid().await?;
    let floor_gid = get_allocator().await.alloc_gid().await?;
    let req_gid = req.gid_number.parse::<i64>().ok();
    let chosen_gid = match req_gid {
        Some(v) if v > floor_gid => {
            get_allocator().await.bump_gid_next_to(v + 1).await?;
            v
        }
        _ => floor_gid,
    };
    let created_upg = ensure_upg_posix_group(ldap, &req.uid, chosen_gid).await?;
    let user_dn = format!("uid={},{}", req.uid, user_ou);
    let hashed_password = hash_password(&req.user_password);
    let uid_number = uid_number.to_string();
    let chosen_gid = chosen_gid.to_string();
    let mut attrs = HashMap::new();
    attrs.insert("objectClass", vec!["top", "inetOrgPerson", "posixAccount", "shadowAccount"]);
    attrs.insert("uid", vec![req.uid.as_str()]);
    attrs.insert("userPassword", vec![hashed_password.as_str()]);
    attrs.insert("cn", vec![req.cn.as_str()]);
    attrs.insert("sn", vec![req.sn.as_str()]);
    attrs.insert("homeDirectory", vec![req.home_directory.as_str()]);
    attrs.insert("loginShell", vec![req.login_shell.as_str()]);
    attrs.insert("givenName", vec![req.given_name.as_str()]);
    attrs.insert("displayName", vec![req.display_name.as_str()]);
    attrs.insert("uidNumber", vec![&uid_number]);
    attrs.insert("gidNumber", vec![&chosen_gid]);
    attrs.insert("gecos", vec![req.gecos.as_str()]);
    let attributes = map_to_attrs(attrs);

    match ldap.add(&user_dn, attributes).await?.success() {
        Ok(_) => Ok(()),
        Err(e) => {
            if created_upg {
                let _ = ldap.delete(&upg_dn_of(&req.uid)).await;
            }
            Err(e.into())
        }
    }
}

pub(crate) async fn delete_user_impl(ldap: &mut Ldap, req: UserIdRequest) -> SrvResult<()> {
    let dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    let upg_dn = must_find_upg_dn_by_uid(ldap, &req.uid).await?;
    ldap.delete(&dn).await?.success()?;
    ldap.delete(&upg_dn).await?.success()?;
    Ok(())
}

pub(crate) async fn modify_user_impl(ldap: &mut Ldap, req: ModifyUserRequest) -> SrvResult<()> {
    let dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    let changes: Vec<Mod<String>> = req
        .changes
        .into_iter()
        .map(|(k, v)| {
            let value = if k == "userPassword" { hash_password(&v) } else { v.to_string() };
            Mod::Replace(k, vec![value].into_iter().collect())
        })
        .collect();

    ldap.modify(&dn, changes).await?.success()?;
    Ok(())
}

pub(crate) async fn list_user_impl(ldap: &mut Ldap) -> SrvResult<Vec<String>> {
    let ubase = users_base();
    let filter = "(objectClass=inetOrgPerson)";
    let (results, _) =
        ldap.search(&ubase, Scope::OneLevel, filter, vec!["uid"]).await?.success()?;
    let users: Vec<String> = results
        .into_iter()
        .filter_map(|entry| {
            let entry = SearchEntry::construct(entry);
            entry.attrs.get("uid").and_then(|v| v.first()).cloned()
        })
        .collect();
    Ok(users)
}

pub(crate) async fn search_user_impl(
    ldap: &mut Ldap,
    req: UserIdRequest,
) -> SrvResult<UserDetailResponse> {
    let ubase = users_base();
    let filter = format!("(uid={})", req.uid);
    let results = match ldap.search(&ubase, Scope::OneLevel, &filter, vec!["*"]).await?.success() {
        Ok((res, _)) => res,
        Err(_) => return Err(LdapServiceError::UserNotFound(req.uid.to_string())),
    };
    let entry = SearchEntry::construct(results[0].clone());
    let attrs = &entry.attrs;
    let resp = UserDetailResponse {
        uid:            attrs.get("uid").and_then(|v| v.first()).cloned().unwrap_or_default(),
        cn:             attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default(),
        sn:             attrs.get("sn").and_then(|v| v.first()).cloned().unwrap_or_default(),
        uid_number:     attrs.get("uidNumber").and_then(|v| v.first()).cloned().unwrap_or_default(),
        gid_number:     attrs.get("gidNumber").and_then(|v| v.first()).cloned().unwrap_or_default(),
        home_directory: attrs
            .get("homeDirectory")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        login_shell:    attrs
            .get("loginShell")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        given_name:     attrs.get("givenName").and_then(|v| v.first()).cloned().unwrap_or_default(),
        display_name:   attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default(),
        gecos:          attrs.get("gecos").and_then(|v| v.first()).cloned().unwrap_or_default(),
    };
    Ok(resp)
}

pub(crate) async fn authenticate_user_impl(
    ldap: &mut Ldap,
    req: AuthRequest,
) -> SrvResult<AuthResponse> {
    let base_dn = base_dn();
    let filter = format!("(uid={})", req.uid);
    let results = match ldap
        .search(&base_dn, Scope::Subtree, &filter, vec!["dn", "shadowExpire"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => return Ok(AuthResponse { success: false, message: "User not found".into() }),
    };

    let entry = SearchEntry::construct(results[0].clone());
    if let Some(vals) = entry.attrs.get("shadowExpire") {
        if let Some(v) = vals.first() {
            if is_shadow_locked(v) {
                return Ok(AuthResponse {
                    success: false,
                    message: "Account locked (shadowExpire)".into(),
                });
            }
        }
    }
    let auth_ok = ldap.simple_bind(&entry.dn, &req.user_password).await?.success().is_ok();
    if auth_ok {
        Ok(AuthResponse { success: true, message: "Authenticated".into() })
    } else {
        Ok(AuthResponse { success: false, message: "Invalid credentials".into() })
    }
}

pub(crate) async fn toggle_user_status_impl(
    ldap: &mut Ldap,
    req: ToggleUserStatusRequest,
) -> SrvResult<GenericResponse> {
    let dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    if req.enable {
        let op: Mod<String> = Mod::Delete("shadowExpire".into(), HashSet::<String>::new());
        match ldap.modify(&dn, vec![op]).await?.success() {
            Ok(_) => Ok(GenericResponse {
                success: true,
                message: format!("User '{}' has been enabled.", req.uid),
            }),
            Err(e) if is_no_such_attribute(&e) => Ok(GenericResponse {
                success: true,
                message: format!("User '{}' has been enabled.", req.uid),
            }),
            Err(e) if is_no_such_object(&e) => Err(LdapServiceError::UserNotFound(req.uid.clone())),
            Err(e) => Err(e.into()),
        }
    } else {
        let mut hs = HashSet::new();
        hs.insert("1".to_string());
        let op: Mod<String> = Mod::Replace("shadowExpire".into(), hs);
        match ldap.modify(&dn, vec![op]).await?.success() {
            Ok(_) => Ok(GenericResponse {
                success: true,
                message: format!("User '{}' has been disabled.", req.uid),
            }),
            Err(e) if is_no_such_object(&e) => Err(LdapServiceError::UserNotFound(req.uid.clone())),
            Err(e) => Err(e.into()),
        }
    }
}

pub(crate) async fn add_group_impl(ldap: &mut Ldap, req: GroupRequest) -> SrvResult<()> {
    let gbase = groups_base();
    let filter = format!("(cn={})", req.group_name);
    if search_one(ldap, &gbase, Scope::OneLevel, &filter, vec!["dn"]).await?.is_some() {
        return Err(LdapServiceError::GroupAlreadyExists(req.group_name.clone()));
    }
    let dn = format!("cn={},{}", req.group_name, gbase);
    let gid_number = get_allocator().await.alloc_gid().await?.to_string();
    let mut attrs = HashMap::new();
    attrs.insert("objectClass", vec!["posixGroup", "top"]);
    attrs.insert("cn", vec![req.group_name.as_str()]);
    attrs.insert("gidNumber", vec![&*gid_number]);
    let attributes = map_to_attrs(attrs);
    ldap.add(&dn, attributes).await?.success()?;
    Ok(())
}

pub(crate) async fn delete_group_impl(ldap: &mut Ldap, req: GroupRequest) -> SrvResult<()> {
    let gbase = groups_base();
    let filter = format!("(cn={})", req.group_name);
    if let Some(se) = search_one(ldap, &gbase, Scope::OneLevel, &filter, vec!["dn"]).await? {
        if se.dn == administrators_group() {
            return Err(LdapServiceError::OperationError(
                "Cannot delete the 'administrators' group".into(),
            ));
        }
        ldap.delete(&se.dn).await?.success()?;
        Ok(())
    } else {
        Err(LdapServiceError::GroupNotFound(format!("{} Not found", req.group_name)))
    }
}

pub(crate) async fn search_group_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<GroupDetailResponse> {
    let gbase = groups_base();
    let dn = format!("cn={},{}", req.group_name, gbase);
    let results = match ldap
        .search(&dn, Scope::Base, "(objectClass=posixGroup)", vec!["*"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::GroupNotFound(format!("{} Not found", req.group_name)))
        }
    };
    let entry = SearchEntry::construct(results[0].clone());
    let attrs = &entry.attrs;
    let resp = GroupDetailResponse {
        cn:         attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default(),
        gidnumber:  attrs.get("gidNumber").and_then(|v| v.first()).cloned().unwrap_or_default(),
        member_uid: attrs.get("memberUid").cloned().unwrap_or_default(),
    };
    Ok(resp)
}
pub(crate) async fn list_group_impl(ldap: &mut Ldap) -> SrvResult<GroupListResponse> {
    let gbase = groups_base();
    let results = match ldap
        .search(&gbase, Scope::OneLevel, "(objectClass=posixGroup)", vec!["cn"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::OperationError("LDAP search operation failed".into()))
        }
    };
    let groups: Vec<String> = results
        .into_iter()
        .filter_map(|e| {
            let entry = SearchEntry::construct(e);
            entry.attrs.get("cn").and_then(|v| v.first()).cloned()
        })
        .collect();
    Ok(GroupListResponse { groups })
}

pub(crate) async fn add_user_to_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let gbase = groups_base();
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);
    if ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success().is_err() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is already a member of group '{}'",
            req.uid, req.group_name
        )));
    }

    let op = Mod::Add("memberUid".into(), vec![req.uid.clone()].into_iter().collect());
    ldap.modify(&group_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        success: true,
        message: format!("User '{}' added to group '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn remove_user_from_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let gbase = groups_base();
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);

    if ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success().is_err() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is not a member of group '{}'",
            req.uid, req.group_name
        )));
    }
    let op = Mod::Delete("memberUid".into(), vec![req.uid.clone()].into_iter().collect());
    ldap.modify(&group_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        success: true,
        message: format!("User '{}' removed from group '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn list_user_in_group_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<UserListResponse> {
    let gbase = groups_base();
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let results = match ldap
        .search(&group_dn, Scope::Base, "(objectClass=posixGroup)", vec!["memberUid"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::GroupNotFound(format!("{} Not found", req.group_name)))
        }
    };
    let entry = SearchEntry::construct(results[0].clone());
    let users = entry
        .attrs
        .get("memberUid")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    Ok(UserListResponse { users })
}

pub(crate) async fn search_user_in_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let gbase = groups_base();
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);
    let results =
        match ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success() {
            Ok((res, _)) => res,
            Err(_) => {
                return Err(LdapServiceError::OperationError(
                    "Search User in Group failed".to_string(),
                ))
            }
        };
    let found = !results.is_empty();
    Ok(GenericResponse {
        success: found,
        message: if found {
            format!("User '{}' is in group '{}'.", req.uid, req.group_name)
        } else {
            format!("User '{}' is NOT in group '{}'.", req.uid, req.group_name)
        },
    })
}

pub(crate) async fn add_web_role_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<GenericResponse> {
    let wbase = web_base();
    let filter = format!("(cn={})", req.group_name);
    if search_one(ldap, &wbase, Scope::OneLevel, &filter, vec!["dn"]).await?.is_some() {
        return Err(LdapServiceError::GroupAlreadyExists(req.group_name.clone()));
    }
    let dn = format!("cn={},{}", req.group_name, wbase);
    let mut attrs = HashMap::new();
    attrs.insert("objectClass", vec!["top", "groupOfNames"]);
    attrs.insert("cn", vec![req.group_name.as_str()]);
    attrs.insert("member", vec![dn.as_str()]);
    let attributes = map_to_attrs(attrs);
    ldap.add(&dn, attributes).await?.success()?;
    Ok(GenericResponse {
        success: true,
        message: format!("Web role '{}' has been created.", req.group_name),
    })
}

pub(crate) async fn delete_web_role_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<GenericResponse> {
    let wbase = web_base();
    let filter = format!("(cn={})", req.group_name);
    if let Some(se) = search_one(ldap, &wbase, Scope::OneLevel, &filter, vec!["dn"]).await? {
        ldap.delete(&se.dn).await?.success()?;
        Ok(GenericResponse {
            success: true,
            message: format!("Web role '{}' has been deleted.", req.group_name),
        })
    } else {
        Err(LdapServiceError::GroupNotFound(format!("Web role '{}' Not found", req.group_name)))
    }
}

pub(crate) async fn list_web_roles_impl(ldap: &mut Ldap) -> SrvResult<GroupListResponse> {
    let wbase = web_base();
    let results = match ldap
        .search(&wbase, Scope::OneLevel, "(objectClass=groupOfNames)", vec!["cn"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => return Err(LdapServiceError::OperationError("List Web Role failed".into())),
    };
    let roles: Vec<String> = results
        .into_iter()
        .filter_map(|e| {
            let entry = SearchEntry::construct(e);
            entry.attrs.get("cn").and_then(|v| v.first()).cloned()
        })
        .collect();
    Ok(GroupListResponse { groups: roles })
}

pub(crate) async fn search_web_role_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<WebRoleDetailResponse> {
    let wbase = web_base();
    let dn = format!("cn={},{wbase}", req.group_name);
    let results = match ldap
        .search(&dn, Scope::Base, "(objectClass=groupOfNames)", vec!["*"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::GroupNotFound(format!(
                "Web role '{}' Not found",
                req.group_name
            )))
        }
    };

    let entry = SearchEntry::construct(results[0].clone());
    let attrs = &entry.attrs;

    let group_dn = entry.dn.clone();
    let members: Vec<String> = attrs
        .get("member")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m != &group_dn)
        .collect();

    let resp = WebRoleDetailResponse {
        cn:         attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default(),
        member_uid: members,
    };
    Ok(resp)
}

pub(crate) async fn add_user_to_web_role_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let wbase = web_base();
    let role_dn = format!("cn={},{}", req.group_name, wbase);
    let filter = format!("(member={})", req.uid);
    if ldap.search(&role_dn, Scope::Base, &filter, vec!["member"]).await?.success().is_err() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is already a member of web role '{}'",
            req.uid, req.group_name
        )));
    }
    let user_dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    let op = Mod::Add("member", vec![&*user_dn].into_iter().collect());
    ldap.modify(&role_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        success: true,
        message: format!("User '{}' added to web role '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn remove_user_from_web_role_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let wbase = web_base();
    let role_dn = format!("cn={},{}", req.group_name, wbase);
    let filter = format!("(member={})", req.uid);
    if ldap.search(&role_dn, Scope::Base, &filter, vec!["member"]).await?.success().is_err() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is not a member of web role '{}'",
            req.uid, req.group_name
        )));
    }
    let user_dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    let op = Mod::Delete("member", vec![&*user_dn].into_iter().collect());
    ldap.modify(&role_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        success: true,
        message: format!("User '{}' removed from web role '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn list_user_in_web_role_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<UserListResponse> {
    let wbase = web_base();
    let role_dn = format!("cn={},{}", req.group_name, wbase);
    let results = match ldap
        .search(&role_dn, Scope::Base, "(objectClass=groupOfNames)", vec!["member"])
        .await?
        .success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::GroupNotFound(format!(
                "Web role '{}' Not found",
                req.group_name
            )))
        }
    };
    let entry = SearchEntry::construct(results[0].clone());
    let group_dn = entry.dn.clone();
    let users: Vec<String> = entry
        .attrs
        .get("member")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m != &group_dn)
        .collect();
    Ok(UserListResponse { users })
}

pub(crate) async fn search_user_in_web_role_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let wbase = web_base();
    let role_dn = format!("cn={},{wbase}", req.group_name);
    let user_dn = must_find_dn_by_uid(ldap, &req.uid).await?;
    let filter = format!("(member={user_dn})");
    let results = match ldap.search(&role_dn, Scope::Base, &filter, vec!["member"]).await?.success()
    {
        Ok((res, _)) => res,
        Err(_) => {
            return Err(LdapServiceError::OperationError(
                "Search User in Web Role failed".to_string(),
            ))
        }
    };
    let found = !results.is_empty();
    Ok(GenericResponse {
        success: found,
        message: if found {
            format!("User '{}' is in web role '{}'.", req.uid, req.group_name)
        } else {
            format!("User '{}' is NOT in web role '{}'.", req.uid, req.group_name)
        },
    })
}
