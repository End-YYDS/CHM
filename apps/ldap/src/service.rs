// ============================================================
// ======================= gRPC Service =======================
// ============================================================

use std::{fmt::Display, future::Future, pin::Pin, sync::Arc};

use crate::{error::SrvResult, srv_impl::*};
use arc_swap::ArcSwapOption;
use chm_grpc::{
    ldap::{
        ldap_service_server::LdapService, AuthRequest, AuthResponse, Empty, GenericResponse,
        GroupDetailResponse, GroupIdRequest, GroupListResponse, GroupNameResponse, GroupRequest,
        ModifyGroupNameRequest, ModifyUserRequest, ToggleUserStatusRequest, UserDetailResponse,
        UserGroupRequest, UserIdRequest, UserListResponse, UserRequest, WebRoleDetailResponse,
    },
    tonic::{async_trait, Request, Response, Status},
};
use ldap3::{Ldap, LdapConnAsync};
use tokio::{sync::Mutex, task::JoinHandle};

#[derive(Debug)]
struct LdapConnState {
    ldap: Mutex<Ldap>,
    _deriver: JoinHandle<()>,
}

#[derive(Debug)]
pub struct LdapManager {
    url: String,
    bind_dn: String,
    bind_pw: String,
    state: ArcSwapOption<LdapConnState>,
    connect_lock: Mutex<()>,
}
impl LdapManager {
    pub fn new(url: String, bind_dn: String, bind_pw: String) -> Self {
        Self {
            url,
            bind_dn,
            bind_pw,
            state: ArcSwapOption::from(None),
            connect_lock: Mutex::new(()),
        }
    }
    async fn connect_fresh(&self) -> SrvResult<Arc<LdapConnState>> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.url).await?;
        let driver = tokio::spawn(async move {
            ldap3::drive!(conn);
        });
        ldap.simple_bind(&self.bind_dn, &self.bind_pw).await?.success()?;
        Ok(Arc::new(LdapConnState { ldap: Mutex::new(ldap), _deriver: driver }))
    }
    async fn ensure_alive(&self) -> SrvResult<Arc<LdapConnState>> {
        if let Some(st) = self.state.load_full() {
            return Ok(st);
        }
        let _g = self.connect_lock.lock().await;
        if let Some(st) = self.state.load_full() {
            return Ok(st);
        }
        let fresh = self.connect_fresh().await?;
        self.state.store(Some(fresh.clone()));
        Ok(fresh)
    }
    pub async fn with_ldap<F, T>(&self, mut f: F) -> SrvResult<T>
    where
        F: for<'a> FnMut(&'a mut Ldap) -> Pin<Box<dyn Future<Output = SrvResult<T>> + Send + 'a>>
            + Send,
        T: Send,
    {
        let st = self.ensure_alive().await?;
        let mut guard = st.ldap.lock().await;
        match f(&mut guard).await {
            Ok(v) => Ok(v),

            Err(e) if is_conn_broken(&e) => {
                drop(guard);
                let _g = self.connect_lock.lock().await;
                let fresh = self.connect_fresh().await?;
                self.state.store(Some(fresh.clone()));
                let mut guard2 = fresh.ldap.lock().await;
                f(&mut guard2).await
            }

            Err(e) => Err(e),
        }
    }
}

fn is_conn_broken<E: Display>(e: &E) -> bool {
    let s = e.to_string();
    s.contains("ConnClosed")
        || s.contains("connection closed")
        || s.contains("I/O error")
        || s.contains("Broken pipe")
        || s.contains("connection reset")
        || s.contains("Transport endpoint")
}

#[derive(Debug)]
pub struct MyLdapService {
    ldap: Arc<LdapManager>,
}
impl MyLdapService {
    pub fn new(url: String, bind_dn: String, bind_pw: String) -> Self {
        Self { ldap: Arc::new(LdapManager::new(url, bind_dn, bind_pw)) }
    }
}

#[async_trait]
impl LdapService for MyLdapService {
    // ---------------- User APIs ----------------
    async fn add_user(
        &self,
        request: Request<UserRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.uid.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { add_user_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("User '{user_id}' added."),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<UserIdRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.uid.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { delete_user_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("User '{user_id}' deleted."),
        }))
    }

    async fn modify_user(
        &self,
        request: Request<ModifyUserRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.uid.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { modify_user_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("User '{user_id}' modified."),
        }))
    }

    async fn list_user(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<UserListResponse>, Status> {
        let users =
            self.ldap.with_ldap(|ldap| Box::pin(async move { list_user_impl(ldap).await })).await?;
        Ok(Response::new(UserListResponse { users }))
    }

    async fn search_user(
        &self,
        request: Request<UserIdRequest>,
    ) -> Result<Response<UserDetailResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { search_user_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn authenticate_user(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { authenticate_user_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn toggle_user_status(
        &self,
        request: Request<ToggleUserStatusRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let ret = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { toggle_user_status_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(ret))
    }

    // ---------------- Group APIs ----------------
    async fn add_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let group_name = req.group_name.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { add_group_impl(ldap, req_cloned).await }))
            })
            .await?;

        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("Group '{group_name}' added."),
        }))
    }

    async fn delete_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let group_name = req.group_name.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { delete_group_impl(ldap, req_cloned).await }))
            })
            .await?;

        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("Group '{group_name}' deleted."),
        }))
    }

    async fn list_group(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GroupListResponse>, Status> {
        let resp = self
            .ldap
            .with_ldap(move |ldap| Pin::from(Box::new(async move { list_group_impl(ldap).await })))
            .await?;
        Ok(Response::new(resp))
    }

    async fn search_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GroupDetailResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { search_group_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn get_group_name(
        &self,
        request: Request<GroupIdRequest>,
    ) -> Result<Response<GroupNameResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { get_group_name_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn modify_group_name(
        &self,
        request: Request<ModifyGroupNameRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let req_for_ldap = req.clone();
        self.ldap
            .with_ldap(move |ldap| {
                let req_clone = req_for_ldap.clone();
                Pin::from(Box::new(async move { modify_group_name_impl(ldap, req_clone).await }))
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to modify group name: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        Ok(Response::new(GenericResponse {
            success: true,
            message: format!("Group '{}' renamed to '{}'", req.old_name, req.new_name),
        }))
    }

    async fn add_web_role(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { add_web_role_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn delete_web_role(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { delete_web_role_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn list_web_role(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GroupListResponse>, Status> {
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                Pin::from(Box::new(async move { list_web_roles_impl(ldap).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn search_web_role(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<WebRoleDetailResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { search_web_role_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn add_user_to_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { add_user_to_group_impl(ldap, req_cloned).await }))
            })
            .await?;

        Ok(Response::new(resp))
    }

    async fn remove_user_from_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(
                    async move { remove_user_from_group_impl(ldap, req_cloned).await },
                ))
            })
            .await?;

        Ok(Response::new(resp))
    }

    async fn list_user_in_group(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<UserListResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move { list_user_in_group_impl(ldap, req_cloned).await }))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn search_user_in_group(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(
                    async move { search_user_in_group_impl(ldap, req_cloned).await },
                ))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn add_user_to_web_role(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(
                    async move { add_user_to_web_role_impl(ldap, req_cloned).await },
                ))
            })
            .await?;

        Ok(Response::new(resp))
    }

    async fn remove_user_from_web_role(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(async move {
                    remove_user_from_web_role_impl(ldap, req_cloned).await
                }))
            })
            .await?;

        Ok(Response::new(resp))
    }

    async fn list_user_in_web_role(
        &self,
        request: Request<GroupRequest>,
    ) -> Result<Response<UserListResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(
                    async move { list_user_in_web_role_impl(ldap, req_cloned).await },
                ))
            })
            .await?;
        Ok(Response::new(resp))
    }

    async fn search_user_in_web_role(
        &self,
        request: Request<UserGroupRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let resp = self
            .ldap
            .with_ldap(move |ldap| {
                let req_cloned = req.clone();
                Pin::from(Box::new(
                    async move { search_user_in_web_role_impl(ldap, req_cloned).await },
                ))
            })
            .await?;
        Ok(Response::new(resp))
    }
}
