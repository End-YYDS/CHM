#![allow(dead_code)]

use crate::ConResult;
use chm_grpc::{
    ldap::{
        ldap_service_client::LdapServiceClient, AuthRequest, Empty, GroupDetailResponse,
        GroupIdRequest, GroupNameResponse, GroupRequest, ModifyGroupNameRequest, ModifyUserRequest,
        ToggleUserStatusRequest, UserDetailResponse, UserGroupRequest, UserIdRequest, UserRequest,
        WebRoleDetailResponse,
    },
    tonic::transport::Channel,
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ClientLdap {
    client: LdapServiceClient<Channel>,
}

impl ClientLdap {
    pub fn new(channel: Channel) -> Self {
        tracing::debug!("建立 LDAP 客戶端...");
        let client = LdapServiceClient::new(channel);
        tracing::info!("LDAP 客戶端已建立");
        Self { client }
    }

    pub fn get_client(&self) -> LdapServiceClient<Channel> {
        self.client.clone()
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn add_user(
        &self,
        uid: String,
        user_password: String,
        cn: Option<String>,
        sn: Option<String>,
        home_directory: Option<String>,
        login_shell: Option<String>,
        given_name: Option<String>,
        display_name: Option<String>,
        gid_number: Option<String>,
        gecos: Option<String>,
    ) -> ConResult<bool> {
        let mut client = self.client.clone();
        let cn = cn.unwrap_or(uid.clone());
        let sn = sn.unwrap_or(uid.clone());
        let home_directory = home_directory.unwrap_or(format!("/home/{uid}"));
        let login_shell = login_shell.unwrap_or("/bin/bash".to_string());
        let given_name = given_name.unwrap_or(uid.clone());
        let display_name = display_name.unwrap_or(uid.clone());
        let gid_number = gid_number.unwrap_or_default();
        let gecos = gecos.unwrap_or_default();
        let req = UserRequest {
            uid,
            user_password,
            cn,
            sn,
            home_directory,
            login_shell,
            given_name,
            display_name,
            gid_number,
            gecos,
        };
        let resp = client.add_user(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn delete_user(&self, uid: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserIdRequest { uid };
        let resp = client.delete_user(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn modify_user(&self, uid: String, attr: HashMap<String, String>) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = ModifyUserRequest { uid, changes: attr };
        let resp = client.modify_user(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn list_users(&self) -> ConResult<Vec<String>> {
        let mut client = self.client.clone();
        let resp = client.list_user(Empty {}).await?.into_inner().users;
        Ok(resp)
    }
    pub async fn search_user(&self, uid: String) -> ConResult<UserDetailResponse> {
        let mut client = self.client.clone();
        let req = UserIdRequest { uid };
        let resp = client.search_user(req).await?.into_inner();
        Ok(resp)
    }
    pub async fn authenticate_user(&self, uid: String, user_password: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = AuthRequest { uid, user_password };
        let resp = client.authenticate_user(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn toggle_user_lock(&self, uid: String, enable: bool) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = ToggleUserStatusRequest { uid, enable };
        let resp = client.toggle_user_status(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn add_group(&self, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.add_group(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn delete_group(&self, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.delete_group(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn list_groups(&self) -> ConResult<Vec<String>> {
        let mut client = self.client.clone();
        let resp = client.list_group(Empty {}).await?.into_inner().groups;
        Ok(resp)
    }
    pub async fn search_group(&self, group_name: String) -> ConResult<GroupDetailResponse> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.search_group(req).await?.into_inner();
        Ok(resp)
    }
    pub async fn get_group_name(&self, gid_number: String) -> ConResult<GroupNameResponse> {
        let mut client = self.client.clone();
        let req = GroupIdRequest { gid_number };
        let resp = client.get_group_name(req).await?.into_inner();
        Ok(resp)
    }
    pub async fn modify_group_name(&self, gid_number: String, new_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = ModifyGroupNameRequest { old_name: gid_number, new_name };
        let resp = client.modify_group_name(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn add_user_to_group(&self, uid: String, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name };
        let resp = client.add_user_to_group(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn remove_user_from_group(&self, uid: String, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name };
        let resp = client.remove_user_from_group(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn list_user_in_group(&self, group_name: String) -> ConResult<Vec<String>> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.list_user_in_group(req).await?.into_inner().users;
        Ok(resp)
    }
    pub async fn search_user_in_group(&self, uid: String, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name };
        let resp = client.search_user_in_group(req).await?.into_inner().success;
        Ok(resp)
    }
    #[allow(unreachable_code)]
    #[allow(clippy::diverging_sub_expression)]
    // TODO: 修改顏色相關參數
    pub async fn add_web_role(&self, _group_name: String) -> ConResult<bool> {
        // let client = self.client.clone();
        // let req = AddWebRoleRequest {
        //     role_name: group_name,
        //     color: todo!("Color.RED as i32"),
        //     color_number: todo!(""),
        //     permission: todo!("8"),
        // };
        // let resp = client.add_web_role(req).await?.into_inner().success;
        // Ok(resp)
        todo!()
    }
    pub async fn delete_web_role(&self, group_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.delete_web_role(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn list_web_roles(&self) -> ConResult<Vec<String>> {
        let mut client = self.client.clone();
        let resp = client.list_web_role(Empty {}).await?.into_inner().groups;
        Ok(resp)
    }
    pub async fn search_web_role(&self, group_name: String) -> ConResult<WebRoleDetailResponse> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name };
        let resp = client.search_web_role(req).await?.into_inner();
        Ok(resp)
    }
    pub async fn add_user_to_web_role(&self, uid: String, role_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name: role_name };
        let resp = client.add_user_to_web_role(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn remove_user_from_web_role(
        &self,
        uid: String,
        role_name: String,
    ) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name: role_name };
        let resp = client.remove_user_from_web_role(req).await?.into_inner().success;
        Ok(resp)
    }
    pub async fn list_user_in_web_role(&self, role_name: String) -> ConResult<Vec<String>> {
        let mut client = self.client.clone();
        let req = GroupRequest { group_name: role_name };
        let resp = client.list_user_in_web_role(req).await?.into_inner().users;
        Ok(resp)
    }
    pub async fn search_user_in_web_role(&self, uid: String, role_name: String) -> ConResult<bool> {
        let mut client = self.client.clone();
        let req = UserGroupRequest { uid, group_name: role_name };
        let resp = client.search_user_in_group(req).await?.into_inner().success;
        Ok(resp)
    }
}
