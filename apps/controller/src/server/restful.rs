#![allow(dead_code, unused_variables)]

use crate::{communication::GrpcClients, GlobalConfig};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::ServiceDescriptor;
use chm_grpc::{
    common::{ResponseResult, ResponseType},
    restful::{restful_service_server::RestfulService, *},
    tonic,
    tonic::{Request, Response, Status},
    tonic_health::{
        pb::{health_client::HealthClient, HealthCheckRequest},
        ServingStatus,
    },
};
use chm_project_const::uuid::Uuid;
use futures::future::join_all;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::{sync::Semaphore, task::JoinSet};

// TODO: 由RestFul Server 為Client 調用Controller RestFul gRPC介面
#[derive(Debug)]
pub struct ControllerRestfulServer {
    pub grpc_clients: Arc<GrpcClients>,
    pub config: (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
}

#[tonic::async_trait]
impl RestfulService for ControllerRestfulServer {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        // let resp = with_ldap!(
        //     self.grpc_clients,
        //     crate::communication::PickStrategy::Random {
        //         attempts: GlobalConfig::with(|cfg| cfg.extend.service_attempts)
        //     },
        //     |ldap| ldap.authenticate_user(req.username.clone(), req.password).await
        // );
        let req_username_clone = req.username.clone();
        let resp = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                ldap.authenticate_user(req_username_clone, req.password).await
            })
            .await;
        let res = resp.map_err(|e| Status::internal(e.to_string()))?;
        if !res {
            Err(Status::permission_denied(format!("Invalid credentials for user {}", req.username)))
        } else {
            let resp = LoginResponse {
                result: Some(ResponseResult {
                    r#type: ResponseType::Ok as i32,
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
        let r = self
            .grpc_clients
            .with_ca_handle(|ca| async move { ca.get_all_certificates().await })
            .await
            .map_err(|e| Status::internal(format!("Failed to get valid certificates: {e}")))?;
        let vaild_certs: Vec<ValidCert> = r
            .iter()
            .map(|cert| ValidCert {
                name: cert.subject_cn.clone(),
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
        let r = self
            .grpc_clients
            .with_ca_handle(|ca| async move { ca.get_all_revoked_certificates().await })
            .await
            .map_err(|e| Status::internal(format!("Failed to get revoked certificates: {e}")))?;
        let revoked_certs: Vec<RevokedCert> = r
            .iter()
            .map(|entry| RevokedCert {
                number: entry.cert_serial.clone(),
                time: entry.revoked_at.as_ref().map(CertUtils::ts_to_string).unwrap_or_default(),
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
        // let cert = with_ca!(
        //     self.grpc_clients,
        //     crate::communication::PickStrategy::Random {
        //         attempts: GlobalConfig::with(|cfg| cfg.extend.service_attempts)
        //     },
        //     |ca| ca.get_certificate_by_common_name(&name).await
        // )
        // .map_err(|e| Status::internal(format!("Failed to get serail {name}")))?;
        let name_cloned = name.clone();
        let cert = self
            .grpc_clients
            .with_ca_handle(|ca| async move {
                ca.get_certificate_by_common_name(name_cloned.clone()).await
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to get serail {name}: {e}")))?;
        let cert = match cert {
            Some(c) => c,
            None => return Err(Status::not_found(format!("Certificate {name} not found"))),
        };
        // let name_cloned = name.clone();
        self.grpc_clients
            .with_ca_handle(|ca| async move {
                ca.mark_certificate_as_revoked(cert.serial, Some(reason)).await
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke certificate {name}: {e}")))?;
        // TODO: 等到後面Agent成功合併之後，需要修改
        let (pri_key, same_name_csr) = CertUtils::generate_csr_with_new_key(
            4096,
            "TW",
            "Taipei",
            "Taipei",
            "CHM.com",
            &name,
            ["127.0.0.1", &name],
        )
        .map_err(|e| Status::internal(e.to_string()))?;
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        self.grpc_clients
            .with_ca_handle(|ca| async move { ca.sign_certificate(same_name_csr, sign_days).await })
            .await
            .map_err(|e| Status::internal(format!("Failed to sign certificate: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("憑證 {name} 已成功註銷"),
        };
        let resp = RevokeCertResponse { result: Some(result) };
        Ok(Response::new(resp))
    }

    async fn add_pc(
        &self,
        request: Request<AddPcRequest>,
    ) -> Result<Response<AddPcResponse>, Status> {
        use crate::Node;
        let req = request.into_inner();
        // TODO: 預設PC Group 要先在啟動時創建，添加Agent時直接加入預設Group(vni=1)
        let ip: SocketAddr = req.ip.parse().map_err(|e| {
            Status::invalid_argument(format!("Invalid IP address format for '{}': {e}", req.ip))
        })?;
        let node_h = Node::new(
            Some(req.ip),
            Some(req.password),
            self.grpc_clients.clone(),
            self.config.clone(),
        );
        node_h.add(false).await.map_err(|e| Status::internal(e.to_string()))?;
        let resp = AddPcResponse {
            result: Some(ResponseResult {
                r#type: ResponseType::Ok as i32,
                message: "添加主機成功".to_string(),
            }),
        };
        Ok(Response::new(resp))
    }

    async fn get_all_pcs(
        &self,
        _request: Request<GetAllPcsRequest>,
    ) -> Result<Response<GetAllPcsResponse>, Status> {
        let services: Vec<ServiceDescriptor> = GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .iter()
                .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
                .collect()
        });
        // TODO: 可能需要檢查API Server 的存活狀態

        let mut pcs: HashMap<String, PcSimple> = HashMap::new();
        for service in services.iter() {
            let mut status = false;

            if let Some(health_name) = service.health_name.as_deref() {
                // 取出該 ServiceKind 的所有連線，逐一檢查
                let channels = self.grpc_clients.all_channels(service.kind);
                if channels.is_empty() {
                    tracing::warn!(
                        "找不到 {:?} 的任何 channel，略過健康檢查（{}）",
                        service.kind,
                        service.hostname
                    );
                } else {
                    for ch in channels {
                        let mut hc = HealthClient::new(ch);
                        match hc
                            .check(HealthCheckRequest { service: health_name.to_string() })
                            .await
                        {
                            Ok(resp) => {
                                let s = resp.into_inner().status;
                                if s == ServingStatus::Serving as i32 {
                                    status = true;
                                    break; // 有一條健康即可
                                }
                            }
                            Err(e) => {
                                tracing::warn!("健康檢查失敗: {} ({})", service.hostname, e);
                            }
                        }
                    }
                }
            } else {
                tracing::info!("{} 未設定 health_name，跳過健康檢查", service.hostname);
            }
            let pc =
                PcSimple { ip: service.uri.clone(), hostname: service.hostname.clone(), status };
            pcs.insert(service.uuid.to_string(), pc);
        }

        let length = pcs.len() as u64;
        Ok(Response::new(GetAllPcsResponse { pcs, length }))
    }
    // TODO: 這裡的status只是先去看healthService的狀態，
    // 後面需要透過heatbeat機制來更新
    async fn get_specific_pcs(
        &self,
        request: Request<GetSpecificPcsRequest>,
    ) -> Result<Response<GetSpecificPcsResponse>, Status> {
        let data = request.into_inner();
        let wanted: HashSet<Uuid> = data
            .uuid
            .into_iter()
            .filter_map(|s| match Uuid::parse_str(&s) {
                Ok(u) => Some(u),
                Err(e) => {
                    tracing::warn!("忽略無效的 UUID '{s}': {e}");
                    None
                }
            })
            .collect();
        let services: HashSet<ServiceDescriptor> = GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .iter()
                .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
                .collect()
        });
        let filtered = services.into_iter().filter(|s| wanted.contains(&s.uuid));
        let mut pcs: HashMap<String, PcSimple> = HashMap::new();
        for service in filtered {
            let mut status = false;

            if let Some(health_name) = service.health_name.as_deref() {
                let channels = self.grpc_clients.all_channels(service.kind);
                if channels.is_empty() {
                    tracing::warn!(
                        "找不到 {:?} 的任何 channel，略過健康檢查（{}）",
                        service.kind,
                        service.hostname
                    );
                } else {
                    for ch in channels {
                        let mut hc = HealthClient::new(ch);
                        match hc
                            .check(HealthCheckRequest { service: health_name.to_string() })
                            .await
                        {
                            Ok(resp) => {
                                let s = resp.into_inner().status;
                                if s == ServingStatus::Serving as i32 {
                                    status = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("健康檢查失敗: {} ({})", service.hostname, e);
                            }
                        }
                    }
                }
            } else {
                tracing::info!("{} 未設定 health_name，跳過健康檢查", service.hostname);
            }

            let pc =
                PcSimple { ip: service.uri.clone(), hostname: service.hostname.clone(), status };
            pcs.insert(service.uuid.to_string(), pc);
        }
        let length = pcs.len() as u64;
        Ok(Response::new(GetSpecificPcsResponse { pcs, length }))
    }

    async fn delete_pcs(
        &self,
        request: Request<DeletePcsRequest>,
    ) -> Result<Response<DeletePcsResponse>, Status> {
        // RestFul API
        // 只能移除Agent，不能移除基礎服務,
        // 必須透過Controller的Cli或後續grpc介面來移除基礎服務
        // TODO: controller lib.rs: Node struct 需要與Agent通訊之後才能移除
        use crate::Node;
        let req = request.into_inner();
        let mut results = HashMap::new();
        for pc in req.uuids {
            let d_pc = GlobalConfig::with(|cfg| {
                cfg.extend.services_pool.services.iter().find_map(|entry| {
                    entry.value().iter().find(|s| s.uuid.to_string() == pc).cloned()
                })
            });
            if d_pc.is_none() {
                results.insert(
                    pc,
                    ResponseResult {
                        r#type: ResponseType::Err as i32,
                        message: "找不到主機資訊".to_string(),
                    },
                );
                continue;
            }
            let d_pc = d_pc.unwrap();
            let d_pc_uuid = d_pc.uuid.to_string();
            let node_h =
                Node::new(Some(d_pc_uuid), None, self.grpc_clients.clone(), self.config.clone());
            if let Err(e) = node_h.remove("agent", false).await {
                results.insert(
                    pc,
                    ResponseResult { r#type: ResponseType::Err as i32, message: format!("{e}") },
                );
                continue;
            }
            results.insert(
                pc,
                ResponseResult {
                    r#type: ResponseType::Ok as i32,
                    message: "刪除主機成功".to_string(),
                },
            );
        }
        let resp = DeletePcsResponse { results };
        Ok(Response::new(resp))
    }

    async fn reboot_pcs(
        &self,
        request: Request<RebootPcsRequest>,
    ) -> Result<Response<RebootPcsResponse>, Status> {
        // 調用Agent的grpc fn
        let req = request.into_inner();
        let uuids = req.uuids;
        let total = uuids.len() as u32;
        let max_concurrent = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        // let mut set: JoinSet<Result<(String, ResponseResult), Status>> = JoinSet::new();
        let mut set: JoinSet<(String, ResponseResult)> = JoinSet::new();
        let mut results = HashMap::new();
        for uuid in uuids {
            let exists = GlobalConfig::with(|cfg| {
                cfg.extend
                    .services_pool
                    .services
                    .iter()
                    .any(|entry| entry.value().iter().any(|s| s.uuid.to_string() == uuid))
            });
            if !exists {
                results.insert(
                    uuid.clone(),
                    ResponseResult {
                        r#type: ResponseType::Err as i32,
                        message: "找不到主機資訊".into(),
                    },
                );
                continue;
            }
            let sem = semaphore.clone();
            let clients = self.grpc_clients.clone();
            set.spawn(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            uuid,
                            ResponseResult {
                                r#type: ResponseType::Err as i32,
                                message: "Semaphore closed".to_string(),
                            },
                        );
                    }
                };
                let ret = clients
                    .with_agent_uuid_handle(
                        &uuid,
                        |agent| async move { agent.reboot_system().await },
                    )
                    .await;
                match ret {
                    Ok(true) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Ok as i32,
                            message: "Reboot succeeded".to_string(),
                        },
                    ),
                    Ok(false) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: "Agent reported failure".to_string(),
                        },
                    ),
                    Err(e) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: format!("RPC error: {e}"),
                        },
                    ),
                }
            });
        }

        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok((uuid, result)) => {
                    results.insert(uuid, result);
                }
                Err(join_err) => {
                    results.insert(
                        format!("unknown-{}", results.len() + 1),
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: format!("Join error: {join_err}"),
                        },
                    );
                }
            }
        }
        Ok(Response::new(RebootPcsResponse { results }))
    }

    async fn shutdown_pcs(
        &self,
        request: Request<ShutdownPcsRequest>,
    ) -> Result<Response<ShutdownPcsResponse>, Status> {
        let req = request.into_inner();
        let uuids = req.uuids;
        let total = uuids.len() as u32;
        let max_concurrent = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut set: JoinSet<(String, ResponseResult)> = JoinSet::new();
        let mut results = HashMap::new();
        for uuid in uuids {
            let exists = GlobalConfig::with(|cfg| {
                cfg.extend
                    .services_pool
                    .services
                    .iter()
                    .any(|entry| entry.value().iter().any(|s| s.uuid.to_string() == uuid))
            });
            if !exists {
                results.insert(
                    uuid.clone(),
                    ResponseResult {
                        r#type: ResponseType::Err as i32,
                        message: "找不到主機資訊".into(),
                    },
                );
                continue;
            }
            let sem = semaphore.clone();
            let clients = self.grpc_clients.clone();
            set.spawn(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            uuid,
                            ResponseResult {
                                r#type: ResponseType::Err as i32,
                                message: "Semaphore closed".to_string(),
                            },
                        );
                    }
                };
                let ret = clients
                    .with_agent_uuid_handle(
                        &uuid,
                        |agent| async move { agent.shutdown_system().await },
                    )
                    .await;
                match ret {
                    Ok(true) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Ok as i32,
                            message: "Shutdown succeeded".to_string(),
                        },
                    ),
                    Ok(false) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: "Agent reported failure".to_string(),
                        },
                    ),
                    Err(e) => (
                        uuid,
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: format!("RPC error: {e}"),
                        },
                    ),
                }
            });
        }
        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok((uuid, result)) => {
                    results.insert(uuid, result);
                }
                Err(join_err) => {
                    results.insert(
                        format!("unknown-{}", results.len() + 1),
                        ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: format!("Join error: {join_err}"),
                        },
                    );
                }
            }
        }
        Ok(Response::new(ShutdownPcsResponse { results }))
    }

    async fn get_pc_groups(
        &self,
        request: Request<GetPcGroupsRequest>,
    ) -> Result<Response<GetPcGroupsResponse>, Status> {
        let (groups, length) = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let zones = dhcp
                    .list_zones()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list DHCP zones: {e}")))?;
                let mut groups: HashMap<i64, PcGroup> = HashMap::new();
                for zone in zones {
                    dbg!(&zone);
                    let id = zone.vni;
                    let zone_name = zone.name;
                    let pcs = dhcp
                        .list_pcs_in_zone(&zone_name)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?;
                    let group = PcGroup { groupname: zone_name, pcs };
                    groups.insert(id, group);
                }
                let length = groups.len() as u64;
                Ok((groups, length))
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))?;
        let resp = GetPcGroupsResponse { groups, length };
        Ok(Response::new(resp))
    }

    async fn create_pc_group(
        &self,
        request: Request<CreatePcGroupRequest>,
    ) -> Result<Response<CreatePcGroupResponse>, Status> {
        let req = request.into_inner();
        // let dhcp = self
        //     .grpc_clients
        //     .dhcp()
        //     .ok_or_else(|| Status::internal("DHCP client not initialized"))?;
        let result = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let vni = dhcp
                    .list_zones()
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .last()
                    .map(|zone| zone.vni + 1)
                    .unwrap_or(10);
                let status = dhcp
                    .create_zone(req.groupname, vni, req.cidr)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                if !status {
                    Ok(ResponseResult {
                        r#type: ResponseType::Err as i32,
                        message: "Failed to create PC group".to_string(),
                    })
                } else {
                    Ok(ResponseResult {
                        r#type: ResponseType::Ok as i32,
                        message: "PC group created successfully".to_string(),
                    })
                }
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))?;
        let result = Some(result);
        let resp = CreatePcGroupResponse { result };
        Ok(Response::new(resp))
    }

    async fn put_pc_group(
        &self,
        request: Request<PutPcGroupRequest>,
    ) -> Result<Response<PutPcGroupResponse>, Status> {
        let req = request.into_inner();
        let final_pcs_resp = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let vxlanid = req.vxlanid;
                let group =
                    req.group.ok_or_else(|| Status::invalid_argument("PcGroup is required"))?;
                let detail = dhcp
                    .get_zone_detail_by_vni(vxlanid)
                    .await
                    .map_err(|e| Status::internal(format!("get_zone_detail_by_vni failed: {e}")))?;
                if !group.groupname.is_empty() && group.groupname != detail.name {
                    dhcp.update_zone_name_by_vni(vxlanid, group.groupname.clone()).await.map_err(
                        |e| Status::internal(format!("update_zone_name_by_vni failed: {e}")),
                    )?;
                }
                let desired_uuid_set: HashSet<String> = group
                    .pcs
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let current_pcs_resp =
                    dhcp.list_pcs_in_zone_by_vni(vxlanid).await.map_err(|e| {
                        Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}"))
                    })?;
                let current_uuid_set: HashSet<String> = current_pcs_resp.into_iter().collect();
                let to_add: Vec<String> =
                    desired_uuid_set.difference(&current_uuid_set).cloned().collect();
                let to_remove: Vec<String> =
                    current_uuid_set.difference(&desired_uuid_set).cloned().collect();
                let add_futs = to_add.iter().map(|uuid| {
                    let c = dhcp.clone();
                    let uuid = uuid.clone();
                    async move { c.add_pc_to_zone_by_vni(vxlanid, uuid).await }
                });
                let remove_futs = to_remove.iter().map(|uuid| {
                    let c = dhcp.clone();
                    let uuid = uuid.clone();
                    async move { c.remove_pc_from_zone_by_vni(vxlanid, uuid).await }
                });
                let _add_results = join_all(add_futs).await;
                let _remove_results = join_all(remove_futs).await;
                let final_pcs_resp = dhcp.list_pcs_in_zone_by_vni(vxlanid).await.map_err(|e| {
                    Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}"))
                })?;
                Ok(final_pcs_resp)
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))?;
        let resp = PutPcGroupResponse {
            result: Some(ResponseResult {
                r#type: ResponseType::Ok as i32,
                message: format!(
                    "PC group updated successfully, total PCs: {}",
                    final_pcs_resp.len()
                ),
            }),
        };
        Ok(Response::new(resp))
    }

    async fn patch_pc_group(
        &self,
        request: Request<PatchPcGroupRequest>,
    ) -> Result<Response<PatchPcGroupResponse>, Status> {
        let req = request.into_inner();
        // let dhcp = self
        //     .grpc_clients
        //     .dhcp()
        //     .ok_or_else(|| Status::internal("DHCP client not initialized"))?;
        let vni = req.vxlanid;
        let result = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let ret = match req.kind {
                    Some(patch_pc_group_request::Kind::Groupname(new_name)) => {
                        match dhcp.update_zone_name_by_vni(vni, new_name).await {
                            Ok(resp) => {
                                if resp {
                                    ResponseResult {
                                        r#type: ResponseType::Ok as i32,
                                        message: "Zone name updated successfully".to_string(),
                                    }
                                } else {
                                    ResponseResult {
                                        r#type: ResponseType::Err as i32,
                                        message: "Failed to update zone name".to_string(),
                                    }
                                }
                            }
                            Err(e) => ResponseResult {
                                r#type: ResponseType::Err as i32,
                                message: format!("update_zone_name_by_vni failed: {e}"),
                            },
                        }
                    }
                    Some(patch_pc_group_request::Kind::Pcs(pcs_msg)) => {
                        let current = dhcp.list_pcs_in_zone_by_vni(vni).await.map_err(|e| {
                            Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}"))
                        })?;
                        let current_set: HashSet<String> = current.into_iter().collect();
                        let desired_set: HashSet<String> = pcs_msg
                            .pcs
                            .into_iter()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let to_add: Vec<String> =
                            desired_set.difference(&current_set).cloned().collect();
                        let to_remove: Vec<String> =
                            current_set.difference(&desired_set).cloned().collect();
                        let mut set = JoinSet::new();
                        for uuid in &to_add {
                            let c = dhcp.clone();
                            let uuid = uuid.clone();
                            set.spawn(async move {
                                let res = c.add_pc_to_zone_by_vni(vni, uuid.clone()).await;
                                ("add", uuid, res)
                            });
                        }
                        for uuid in &to_remove {
                            let c = dhcp.clone();
                            let uuid = uuid.clone();
                            set.spawn(async move {
                                let res = c.remove_pc_from_zone_by_vni(vni, uuid.clone()).await;
                                ("remove", uuid, res)
                            });
                        }
                        while set.join_next().await.is_some() {}
                        ResponseResult {
                            r#type: ResponseType::Ok as i32,
                            message: "PCs updated successfully".into(),
                        }
                    }
                    None => ResponseResult {
                        r#type: ResponseType::Err as i32,
                        message: "Missing patch kind".into(),
                    },
                };
                Ok(ret)
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))?;
        Ok(Response::new(PatchPcGroupResponse { result: Some(result) }))
    }

    async fn delete_pc_group(
        &self,
        request: Request<DeletePcGroupRequest>,
    ) -> Result<Response<DeletePcGroupResponse>, Status> {
        let req = request.into_inner();
        let result =
            self.grpc_clients
                .with_dhcp_handle(|dhcp| async move {
                    let vni = req.vxlanid;
                    let zone = dhcp.get_zone_detail_by_vni(vni).await.map_err(|e| {
                        Status::internal(format!("get_zone_detail_by_vni failed: {e}"))
                    })?;
                    let res = dhcp.delete_zone(zone.name).await;
                    let result = match res {
                        Ok(_) => ResponseResult {
                            r#type: ResponseType::Ok as i32,
                            message: "Zone deleted successfully".into(),
                        },
                        Err(e) => ResponseResult {
                            r#type: ResponseType::Err as i32,
                            message: format!("Failed to delete zone: {e}"),
                        },
                    };
                    Ok(result)
                })
                .await
                .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))?;
        Ok(Response::new(DeletePcGroupResponse { result: Some(result) }))
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
        let users = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
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
                                username: detail.uid,
                                password: "".to_string(),
                                cn: detail.cn,
                                sn: detail.sn,
                                home_directory: detail.home_directory,
                                shell: detail.login_shell,
                                given_name: detail.given_name,
                                display_name: detail.display_name,
                                gid_number: detail.gid_number,
                                group: vec![group_name],
                                gecos: detail.gecos,
                            };
                            users.insert(uid, entry);
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch details for user {uid}: {e}");
                            continue;
                        }
                    }
                }
                Ok(users)
            })
            .await
            .map_err(|e| Status::internal(format!("Ldap Error: {e}")))?;
        let length = users.len() as u64;
        let resp = GetUsersResponse { users, length };
        Ok(Response::new(resp))
    }

    // TODO: 添加home directory與shell的預設值
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();
        let user = req.user.ok_or_else(|| Status::invalid_argument("User field is required"))?;
        let username = user.username.clone();
        let username_clone = username.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if !user.group.is_empty() {
                    for group_name in user.group.iter() {
                        if group_name == &username_clone {
                            continue;
                        }
                        ldap.search_group(group_name.clone()).await.map_err(|e| {
                            Status::not_found(format!("Group {group_name} not found: {e}"))
                        })?;
                    }
                }
                ldap.add_user(
                    username_clone.clone(),
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
                .await?;
                for group_name in user.group.iter() {
                    if group_name == &username_clone {
                        continue;
                    }
                    ldap.add_user_to_group(username_clone.clone(), group_name.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to add user {username_clone} to group {group_name}: {e}"
                            ))
                        })?;
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功建立"),
        };
        Ok(Response::new(CreateUserResponse { result: Some(result) }))
    }

    async fn put_users(
        &self,
        request: Request<PutUsersRequest>,
    ) -> Result<Response<PutUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;
        let username = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                if users.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one user entry is required").into()
                    );
                }
                let (username, user) = users.iter().next().ok_or_else(|| {
                    Status::invalid_argument("At least one user entry is required")
                })?;
                ldap.search_user(username.clone())
                    .await
                    .map_err(|e| Status::not_found(format!("User {username} not found: {e}")))?;
                if !user.group.is_empty() {
                    for group_name in user.group.iter() {
                        if group_name == username {
                            continue; // 跳過 primary group
                        }
                        if let Err(e) = ldap.search_group(group_name.clone()).await {
                            return Err(Status::not_found(format!(
                                "Group {group_name} not found: {e}"
                            ))
                            .into());
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
                ldap.modify_user(username.clone(), attr).await.map_err(|e| {
                    Status::internal(format!("Failed to modify user {username}: {e}"))
                })?;

                for group_name in user.group.iter() {
                    if group_name == username {
                        continue;
                    }
                    ldap.add_user_to_group(username.clone(), group_name.clone()).await.map_err(
                        |e| {
                            Status::internal(format!(
                                "Failed to add user {username} to group {group_name}: {e}"
                            ))
                        },
                    )?;
                }
                Ok(username.clone())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;

        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功更新"),
        };

        Ok(Response::new(PutUsersResponse { result: Some(result) }))
    }

    async fn patch_users(
        &self,
        request: Request<PatchUsersRequest>,
    ) -> Result<Response<PatchUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;
        // let ldap = self
        //     .grpc_clients
        //     .ldap()
        //     .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        let username = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                if users.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one user entry is required").into()
                    );
                }
                let (username, user) = users.iter().next().ok_or_else(|| {
                    Status::invalid_argument("At least one user entry is required")
                })?;

                if let Err(e) = ldap.search_user(username.clone()).await {
                    return Err(Status::not_found(format!("User {username} not found: {e}")).into());
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
                                "Group {group_name} not found: {e}"
                            ))
                            .into());
                        }
                    }
                }
                ldap.modify_user(username.clone(), attr).await.map_err(|e| {
                    Status::internal(format!("Failed to modify user {username}: {e}"))
                })?;
                Ok(username.clone())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功更新"),
        };
        Ok(Response::new(PatchUsersResponse { result: Some(result) }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();
        let uid = req.uid;
        let uid_clone = uid.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if let Err(e) = ldap.search_user(uid_clone.clone()).await {
                    return Err(
                        Status::not_found(format!("User {uid_clone} not found: {e}")).into()
                    );
                }
                ldap.delete_user(uid_clone.clone()).await.map_err(|e| {
                    Status::internal(format!("Failed to delete user {uid_clone}: {e}"))
                })?;
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("使用者 {uid} 已成功刪除"),
        };
        Ok(Response::new(DeleteUserResponse { result: Some(result) }))
    }

    async fn get_groups(
        &self,
        request: Request<GetGroupsRequest>,
    ) -> Result<Response<GetGroupsResponse>, Status> {
        let groups = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                let gids = ldap
                    .list_groups()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list groups: {e}")))?;
                let mut groups: HashMap<String, GroupInfo> = HashMap::new();
                for gid in gids {
                    match ldap.search_group(gid.clone()).await {
                        Ok(detail) => {
                            let entry =
                                GroupInfo { groupname: detail.cn, users: detail.member_uid };
                            groups.insert(gid, entry);
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch details for group {gid}: {e}");
                            continue;
                        }
                    }
                }
                Ok(groups)
            })
            .await
            .map_err(|e| Status::internal(format!("Ldap Error: {e}")))?;
        let resp = GetGroupsResponse { groups };
        Ok(Response::new(resp))
    }

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let req = request.into_inner();
        let groupname = req.groupname.clone();
        let users = req.users.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                ldap.add_group(groupname.clone()).await.map_err(|e| {
                    Status::internal(format!("Failed to add group {groupname}: {e}"))
                })?;
                for uid in users {
                    ldap.add_user_to_group(uid.clone(), groupname.clone()).await.map_err(|e| {
                        Status::internal(format!(
                            "Failed to add user {uid} to group {groupname}: {e}"
                        ))
                    })?;
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("群組 {} 已成功建立", req.groupname),
        };
        Ok(Response::new(CreateGroupResponse { result: Some(result) }))
    }

    async fn put_groups(
        &self,
        request: Request<PutGroupsRequest>,
    ) -> Result<Response<PutGroupsResponse>, Status> {
        let req = request.into_inner();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                for (old_name, group_info) in req.groups.iter() {
                    let new_name = &group_info.groupname;

                    let group_exists = ldap
                        .search_group(new_name.clone())
                        .await
                        .map(|_| true)
                        .or_else(|_| Ok(false))
                        .map_err(|e: Box<dyn std::error::Error + Send + Sync>| {
                            Status::internal(format!("LDAP search error: {e}"))
                        })?;
                    if old_name != new_name {
                        ldap.modify_group_name(old_name.clone(), new_name.clone()).await.map_err(
                            |e| {
                                Status::internal(format!(
                                    "Failed to rename group {old_name} -> {new_name}: {e}"
                                ))
                            },
                        )?;
                    }
                    let current_users: Vec<String> =
                        ldap.list_user_in_group(new_name.clone()).await.map_err(|e| {
                            Status::internal(format!(
                                "Failed to list users in group {new_name}: {e}"
                            ))
                        })?;
                    let new_users: HashSet<_> = group_info.users.iter().cloned().collect();
                    let current_users_set: HashSet<_> = current_users.into_iter().collect();
                    for uid in new_users.difference(&current_users_set) {
                        ldap.search_user(uid.clone())
                            .await
                            .map_err(|e| Status::not_found(format!("User {uid} not found: {e}")))?;
                        ldap.add_user_to_group(uid.clone(), new_name.clone()).await.map_err(
                            |e| {
                                Status::internal(format!(
                                    "Failed to add user {uid} to group {new_name}: {e}"
                                ))
                            },
                        )?;
                    }
                    for uid in current_users_set.difference(&new_users) {
                        ldap.remove_user_from_group(uid.clone(), new_name.clone()).await.map_err(
                            |e| {
                                Status::internal(format!(
                                    "Failed to remove user {uid} from group {new_name}: {e}"
                                ))
                            },
                        )?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: "群組資料已成功更新".to_string(),
        };
        Ok(Response::new(PutGroupsResponse { result: Some(result) }))
    }

    async fn patch_groups(
        &self,
        request: Request<PatchGroupsRequest>,
    ) -> Result<Response<PatchGroupsResponse>, Status> {
        let req = request.into_inner();
        // let ldap = self
        //     .grpc_clients
        //     .ldap()
        //     .ok_or_else(|| Status::internal("LDAP client not initialized"))?;
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if req.groups.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one group entry is required").into()
                    );
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
                                    Status::internal(format!("LDAP search error: {e}"))
                                })?;
                            if group_exists {
                                return Err(Status::already_exists(format!(
                                    "Group '{new_name}' already exists"
                                ))
                                .into());
                            }
                            ldap.modify_group_name(old_name.clone(), new_name.clone())
                                .await
                                .map_err(|e| {
                                    Status::internal(format!(
                                        "Failed to rename group {old_name} -> {new_name}: {e}"
                                    ))
                                })?;
                        }
                    }
                    if !patch_info.users.is_empty() {
                        let users = &patch_info.users;
                        let group_name = patch_info.groupname.as_ref().unwrap_or(old_name);
                        let current_users =
                            ldap.list_user_in_group(group_name.clone()).await.map_err(|e| {
                                Status::internal(format!(
                                    "Failed to list users in group {group_name}: {e}"
                                ))
                            })?;
                        let current_set: HashSet<_> = current_users.into_iter().collect();
                        let new_set: HashSet<_> = users.iter().cloned().collect();
                        for uid in new_set.difference(&current_set) {
                            ldap.add_user_to_group(uid.clone(), group_name.clone()).await.map_err(
                                |e| Status::internal(format!("Failed to add user {uid}: {e}")),
                            )?;
                        }
                        for uid in current_set.difference(&new_set) {
                            ldap.remove_user_from_group(uid.clone(), group_name.clone())
                                .await
                                .map_err(|e| {
                                    Status::internal(format!("Failed to remove user {uid}: {e}"))
                                })?;
                        }
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
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
        let group_name_clone = group_name.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if let Err(e) = ldap.search_group(group_name_clone.clone()).await {
                    return Err(Status::not_found(format!(
                        "Group {group_name_clone} not found: {e}"
                    ))
                    .into());
                }
                ldap.delete_group(group_name_clone.clone()).await.map_err(|e| {
                    Status::internal(format!("Failed to delete group {group_name_clone}: {e}"))
                })?;
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))?;
        let result = ResponseResult {
            r#type: ResponseType::Ok as i32,
            message: format!("群組 {group_name} 已成功刪除"),
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
