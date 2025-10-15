use crate::{
    allocator::get_allocator,
    error::{LdapServiceError, SrvResult},
    globals::GlobalConfig,
};
use chm_grpc::ldap::{
    AuthRequest, AuthResponse, GenericResponse, GroupDetailResponse, GroupRequest,
    ModifyUserRequest, ToggleUserStatusRequest, UserGroupRequest, UserIdRequest, UserListResponse,
    UserRequest,
};
use ldap3::{Ldap, LdapError, Mod, Scope, SearchEntry};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const OU_USERS: &str = "ou=Users";
const OU_GROUPS: &str = "ou=Groups";
const OU_UPG: &str = "ou=UPG";

const RC_NO_SUCH_ATTRIBUTE: u32 = 16;
const RC_NO_SUCH_OBJECT: u32 = 32;

fn base_dn() -> String {
    GlobalConfig::with(|cfg| cfg.extend.ldap_settings.base_dn.clone())
}
fn users_base(base_dn: &str) -> String {
    format!("{OU_USERS},{base_dn}")
}
fn groups_base(base_dn: &str) -> String {
    format!("{OU_GROUPS},{base_dn}")
}
fn upg_base(base_dn: &str) -> String {
    format!("{OU_UPG},{}", groups_base(base_dn))
}
fn upg_dn_of(uid: &str, base_dn: &str) -> String {
    format!("cn={uid},{}", upg_base(base_dn))
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
async fn must_find_dn_by_uid(ldap: &mut Ldap, uid: &str, base_dn: &str) -> SrvResult<String> {
    let ubase = users_base(base_dn);
    let filter = format!("(uid={uid})");
    if let Some(se) = search_one(ldap, &ubase, Scope::OneLevel, &filter, vec!["dn"]).await? {
        Ok(se.dn)
    } else {
        Err(LdapServiceError::UserNotFound(uid.to_string()))
    }
}

async fn ensure_upg_posix_group(
    ldap: &mut Ldap,
    base_dn: &str,
    uid: &str,
    gid_number: i64,
) -> SrvResult<bool> {
    let g_dn = upg_dn_of(uid, base_dn);
    let filter = format!("(cn={uid})");
    if let Some(se) =
        search_one(ldap, &upg_base(base_dn), Scope::OneLevel, &filter, vec!["dn", "gidNumber"])
            .await?
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
    let user_ou = users_base(&base_dn);
    let filter = format!("(uid={})", req.uid);
    let (results, _) =
        ldap.search(&user_ou, Scope::OneLevel, &filter, vec!["dn"]).await?.success()?;
    if !results.is_empty() {
        return Err(LdapServiceError::UserAlreadyExists(req.uid.clone()));
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
    let created_upg = ensure_upg_posix_group(ldap, &base_dn, &req.uid, chosen_gid).await?;
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
                let _ = ldap.delete(&upg_dn_of(&req.uid, &base_dn)).await;
            }
            Err(e.into())
        }
    }
}

pub(crate) async fn delete_user_impl(ldap: &mut Ldap, req: UserIdRequest) -> SrvResult<()> {
    let base_dn = base_dn();
    let dn = must_find_dn_by_uid(ldap, &req.uid, &base_dn).await?;
    ldap.delete(&dn).await?.success()?;
    Ok(())
}

pub(crate) async fn modify_user_impl(ldap: &mut Ldap, req: ModifyUserRequest) -> SrvResult<()> {
    let base_dn = base_dn();
    let dn = must_find_dn_by_uid(ldap, &req.uid, &base_dn).await?;

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
    let base_dn = base_dn();
    let ubase = users_base(&base_dn);
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

pub(crate) async fn search_user_impl(ldap: &mut Ldap, req: UserIdRequest) -> SrvResult<Value> {
    let base_dn = base_dn();
    let ubase = users_base(&base_dn);
    let filter = format!("(uid={})", req.uid);
    let (results, _) = ldap.search(&ubase, Scope::OneLevel, &filter, vec!["*"]).await?.success()?;
    if results.is_empty() {
        return Err(LdapServiceError::UserNotFound(req.uid.to_string()));
    }
    let entry = SearchEntry::construct(results[0].clone());
    // TODO: 檢查attrs有哪些，並不是所有attrs都會有值
    // let entry = SearchEntry::construct(results[0].clone());
    //     let attrs = &entry.attrs;
    //     let json_map = serde_json::json!({
    //         "uid": attrs.get("uid").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "cn":
    // attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default(),
    //         "sn": attrs.get("sn").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "uidNumber":
    // attrs.get("uidNumber").and_then(|v| v.first()).cloned().unwrap_or_default(),
    //         "gidNumber": attrs.get("gidNumber").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "homeDirectory":
    // attrs.get("homeDirectory").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "loginShell":
    // attrs.get("loginShell").and_then(|v| v.first()).cloned().unwrap_or_default(),
    //         "givenName": attrs.get("givenName").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "displayName":
    // attrs.get("displayName").and_then(|v|
    // v.first()).cloned().unwrap_or_default(),         "gecos":
    // attrs.get("gecos").and_then(|v| v.first()).cloned().unwrap_or_default(),
    //     });
    let json_value = serde_json::to_value(&entry.attrs)?;
    Ok(json_value)
}

pub(crate) async fn authenticate_user_impl(
    ldap: &mut Ldap,
    req: AuthRequest,
) -> SrvResult<AuthResponse> {
    let base_dn = base_dn();
    let filter = format!("(uid={})", req.uid);
    let (results, _) = ldap
        .search(&base_dn, Scope::Subtree, &filter, vec!["dn", "shadowExpire"])
        .await?
        .success()?;
    if results.is_empty() {
        return Ok(AuthResponse { success: false, message: "User not found".into() });
    }
    let entry = SearchEntry::construct(results.into_iter().next().unwrap());
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
    let base = base_dn();
    let dn = must_find_dn_by_uid(ldap, &req.uid, &base).await?;

    if req.enable {
        let op: Mod<String> = Mod::Delete("shadowExpire".into(), HashSet::<String>::new());
        match ldap.modify(&dn, vec![op]).await?.success() {
            Ok(_) => {
                Ok(GenericResponse { message: format!("User '{}' has been enabled.", req.uid) })
            }
            Err(e) if is_no_such_attribute(&e) => {
                Ok(GenericResponse { message: format!("User '{}' has been enabled.", req.uid) })
            }
            Err(e) if is_no_such_object(&e) => Err(LdapServiceError::UserNotFound(req.uid.clone())),
            Err(e) => Err(e.into()),
        }
    } else {
        let mut hs = HashSet::new();
        hs.insert("1".to_string());
        let op: Mod<String> = Mod::Replace("shadowExpire".into(), hs);
        match ldap.modify(&dn, vec![op]).await?.success() {
            Ok(_) => {
                Ok(GenericResponse { message: format!("User '{}' has been disabled.", req.uid) })
            }
            Err(e) if is_no_such_object(&e) => Err(LdapServiceError::UserNotFound(req.uid.clone())),
            Err(e) => Err(e.into()),
        }
    }
}

pub(crate) async fn add_group_impl(ldap: &mut Ldap, req: GroupRequest) -> SrvResult<()> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
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
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    let filter = format!("(cn={})", req.group_name);
    if let Some(se) = search_one(ldap, &gbase, Scope::OneLevel, &filter, vec!["dn"]).await? {
        ldap.delete(&se.dn).await?.success()?;
        Ok(())
    } else {
        Err(LdapServiceError::GroupNotFound(req.group_name.to_string()))
    }
}

pub(crate) async fn list_group_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<GroupDetailResponse> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    if req.group_name.is_empty() {
        let (results, _) = ldap
            .search(&gbase, Scope::OneLevel, "(objectClass=posixGroup)", vec!["cn"])
            .await?
            .success()?;
        let groups: Vec<String> = results
            .into_iter()
            .filter_map(|e| {
                let entry = SearchEntry::construct(e);
                entry.attrs.get("cn").and_then(|v| v.first()).cloned()
            })
            .collect();
        return Ok(GroupDetailResponse { details: groups.join(", ") });
    }
    let dn = format!("cn={},{}", req.group_name, gbase);
    let (results, _) =
        ldap.search(&dn, Scope::Base, "(objectClass=posixGroup)", vec!["*"]).await?.success()?;
    if results.is_empty() {
        return Ok(GroupDetailResponse {
            details: format!("Group '{}' not found.", req.group_name),
        });
    }
    let entry = SearchEntry::construct(results[0].clone());
    let attrs = &entry.attrs;
    let json_map = serde_json::json!({
        "cn": attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default(),
        "gidNumber": attrs.get("gidNumber").and_then(|v| v.first()).cloned().unwrap_or_default(),
        "memberUid": attrs.get("memberUid").cloned().unwrap_or_default(),
    });
    Ok(GroupDetailResponse { details: json_map.to_string() })
}

pub(crate) async fn add_user_to_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);
    let (results, _) =
        ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success()?;
    if !results.is_empty() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is already a member of group '{}'",
            req.uid, req.group_name
        )));
    }
    let op = Mod::Add("memberUid".into(), vec![req.uid.clone()].into_iter().collect());
    ldap.modify(&group_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        message: format!("User '{}' added to group '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn remove_user_from_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);
    let (results, _) =
        ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success()?;
    if results.is_empty() {
        return Err(LdapServiceError::OperationError(format!(
            "User '{}' is not a member of group '{}'",
            req.uid, req.group_name
        )));
    }
    let op = Mod::Delete("memberUid".into(), vec![req.uid.clone()].into_iter().collect());
    ldap.modify(&group_dn, vec![op]).await?.success()?;
    Ok(GenericResponse {
        message: format!("User '{}' removed from group '{}'.", req.uid, req.group_name),
    })
}

pub(crate) async fn list_user_in_group_impl(
    ldap: &mut Ldap,
    req: GroupRequest,
) -> SrvResult<UserListResponse> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let (results, _) = ldap
        .search(&group_dn, Scope::Base, "(objectClass=posixGroup)", vec!["memberUid"])
        .await?
        .success()?;
    if results.is_empty() {
        return Err(LdapServiceError::GroupNotFound(req.group_name.to_string()));
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
    Ok(UserListResponse { users })
}

pub(crate) async fn search_user_in_group_impl(
    ldap: &mut Ldap,
    req: UserGroupRequest,
) -> SrvResult<GenericResponse> {
    let base_dn = base_dn();
    let gbase = groups_base(&base_dn);
    let group_dn = format!("cn={},{}", req.group_name, gbase);
    let filter = format!("(memberUid={})", req.uid);
    let (results, _) =
        ldap.search(&group_dn, Scope::Base, &filter, vec!["memberUid"]).await?.success()?;
    let found = !results.is_empty();
    Ok(GenericResponse {
        message: if found {
            format!("User '{}' is in group '{}'.", req.uid, req.group_name)
        } else {
            format!("User '{}' is NOT in group '{}'.", req.uid, req.group_name)
        },
    })
}
