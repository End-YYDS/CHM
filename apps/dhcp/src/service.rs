use crate::{db::get_db, error::DhcpError, LZone};
use chm_grpc::{
    common::ResponseResult,
    dhcp::{
        dhcp_service_server::DhcpService, AddPcToZoneByVniRequest, AddPcToZoneRequest,
        AllocateIpRequest, AllocateIpResponse, CreateZoneRequest, CreateZoneResponse,
        DeleteZoneRequest, DeleteZoneResponse, Empty, IpList, PcIdentifier, PcList,
        ReleaseIpRequest, ReleaseIpResponse, RemovePcFromZoneByVniRequest, RemovePcFromZoneRequest,
        UpdateZoneNameByVniRequest, VniIdentifier, ZoneDetail, ZoneIdentifier, ZoneList,
    },
    tonic,
    tonic::{Request, Response, Status},
};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

#[derive(Debug, Default)]
pub struct DhcpServiceImpl;

#[tonic::async_trait]
impl DhcpService for DhcpServiceImpl {
    /// 建立一個 DHCP Zone
    /// # 參數
    /// * `request` - CreateZoneRequest
    ///   - `zone_name`: 欲建立的 Zone 名稱
    ///   - `vni`: 對應的 VNI 整數值
    ///   - `cidr`: CIDR 格式的網段 (例如 "192.168.0.0/24")
    ///
    /// # 回傳
    /// * `Result<Response<CreateZoneResponse>, Status>`
    ///   成功時返回建立成功訊息；失敗時返回 gRPC 錯誤狀態
    async fn create_zone(
        &self,
        request: Request<CreateZoneRequest>,
    ) -> Result<Response<CreateZoneResponse>, Status> {
        let db = get_db().await;
        let req = request.into_inner();

        if db.is_zone_exist(&req.zone_name).await? {
            return Err(DhcpError::ZoneExists(req.zone_name).into());
        }
        let network = req.cidr.parse::<IpNetwork>().map_err(|_| DhcpError::InvalidCidr)?;
        if network.is_ipv6() {
            return Err(DhcpError::UnsupportedIpv6.into());
        }
        let prefix = network.prefix();
        if (network.is_ipv4() && prefix >= 31) || (network.is_ipv6() && prefix > 126) {
            return Err(DhcpError::InvalidCidr.into());
        }
        let ips: Vec<String> = match network {
            IpNetwork::V4(n) => n
                .iter()
                .filter(|ip| *ip != n.network() && *ip != n.broadcast())
                .map(|ip| ip.to_string())
                .collect(),
            IpNetwork::V6(n) => {
                n.iter().filter(|ip| *ip != n.network()).map(|ip| ip.to_string()).collect()
            }
        };
        if ips.is_empty() {
            return Err(DhcpError::InvalidCidr.into());
        }
        let ip_list_json = serde_json::to_string(&ips).map_err(DhcpError::JsonError)?;
        let (has_conflict, conflicts) = db.is_ip_conflict(ip_list_json).await?;
        if has_conflict {
            return Err(DhcpError::IpConflict(conflicts).into());
        }
        let (broadcast_str, mask_str) = match network {
            IpNetwork::V4(n) => (n.broadcast().to_string(), n.mask().to_string()),
            IpNetwork::V6(n) => (n.network().to_string(), n.mask().to_string()),
        };
        let zone = LZone {
            id:          0,
            name:        req.zone_name.clone(),
            vni:         req.vni,
            network:     network.to_string(),
            broadcast:   broadcast_str,
            subnet_mask: mask_str,
        };
        let zone_id = db.insert_zone(zone).await?;
        db.insert_ip_pools_bulk(zone_id, &ips, false).await?;
        Ok(Response::new(CreateZoneResponse { message: "Zone created successfully".into() }))
    }

    /// 從指定的 Zone 分配一個可用的 IP
    /// # 參數
    /// * `request` - AllocateIpRequest
    ///   - `zone_name`: 欲分配 IP 的 Zone 名稱
    ///
    /// # 回傳
    /// * `Result<Response<AllocateIpResponse>, Status>` 成功時返回分配的
    ///   IP；失敗時返回 gRPC 錯誤狀態
    async fn allocate_ip(
        &self,
        request: Request<AllocateIpRequest>,
    ) -> Result<Response<AllocateIpResponse>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let id = db.get_zone_id(&req.zone_name).await?;
        let ip = db.get_zone_info_by_id(id).await?;
        let ip = db.remove_ip_pools(ip).await?;
        Ok(Response::new(AllocateIpResponse { ip }))
    }

    /// 將一個 IP 歸還到指定的 Zone
    /// # 參數
    /// * `request` - ReleaseIpRequest
    ///   - `zone_name`: 欲釋放 IP 的 Zone 名稱
    ///   - `ip`: 欲釋放的 IP 位址 (字串格式)
    ///
    /// # 回傳
    /// * `Result<Response<ReleaseIpResponse>, Status>`
    ///   成功時返回釋放成功訊息；失敗時返回 gRPC 錯誤狀態
    async fn release_ip(
        &self,
        request: Request<ReleaseIpRequest>,
    ) -> Result<Response<ReleaseIpResponse>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone = db.get_zone_id(&req.zone_name).await?;
        // Check if the IP is valid
        let ip =
            req.ip.parse::<IpAddr>().map_err(|_| DhcpError::InvalidIpFormat(req.ip.clone()))?;
        db.insert_ip_pool(zone, ip.to_string(), true).await?;
        Ok(Response::new(ReleaseIpResponse { message: "IP released".into() }))
    }

    /// 刪除指定的 DHCP Zone
    /// # 參數
    /// * `request` - DeleteZoneRequest
    ///   - `zone_name`: 欲刪除的 Zone 名稱
    ///
    /// # 回傳
    /// * `Result<Response<DeleteZoneResponse>, Status>`
    ///   成功時返回刪除成功訊息；失敗時返回 gRPC 錯誤狀態
    async fn delete_zone(
        &self,
        request: Request<DeleteZoneRequest>,
    ) -> Result<Response<DeleteZoneResponse>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let exists = db.is_zone_exist(&req.zone_name).await?;
        if !exists {
            return Err(DhcpError::ZoneNotFound.into());
        }
        db.remove_zone_by_name(req.zone_name.as_str()).await?;
        Ok(Response::new(DeleteZoneResponse { message: "Zone deleted".into() }))
    }

    /// 列出所有已建立的 DHCP Zones
    /// # 參數
    /// * `_request` - Empty (無任何欄位)
    ///
    /// # 回傳
    /// * `Result<Response<ZoneList>, Status>` 成功時返回 Zone 列表；失敗時返回
    ///   gRPC 錯誤狀態
    async fn list_zones(&self, _request: Request<Empty>) -> Result<Response<ZoneList>, Status> {
        let db = get_db().await;
        let zones = db.get_all_zones_info().await?;
        Ok(Response::new(ZoneList { zones }))
    }

    /// 列出指定 Zone 目前可用的所有 IP
    /// # 參數
    /// * `request` - ZoneIdentifier
    ///   - `zone_name`: 欲查詢的 Zone 名稱
    ///
    /// # 回傳
    /// * `Result<Response<IpList>, Status>` 成功時返回可用 IP 列表；失敗時返回
    ///   gRPC 錯誤狀態
    async fn list_available_ips(
        &self,
        request: Request<ZoneIdentifier>,
    ) -> Result<Response<IpList>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone = db.get_zone_id(&req.zone_name).await?;
        let ips = db.get_ip_by_zone_id(zone).await?;
        Ok(Response::new(IpList { ips }))
    }

    async fn add_pc_to_zone(
        &self,
        request: Request<AddPcToZoneRequest>,
    ) -> Result<Response<ResponseResult>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone_id = db.get_zone_id(&req.zone_name).await?;
        let inserted = db.add_pc_to_zone(zone_id, &req.pc_uuid, true).await?;
        let (ty, msg) = if inserted {
            (chm_grpc::common::ResponseType::Ok as i32, "PC added to zone".to_string())
        } else {
            (chm_grpc::common::ResponseType::Ok as i32, "PC already in zone".to_string())
        };
        Ok(Response::new(ResponseResult { r#type: ty, message: msg }))
    }

    async fn remove_pc_from_zone(
        &self,
        request: Request<RemovePcFromZoneRequest>,
    ) -> Result<Response<ResponseResult>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone_id = db.get_zone_id(&req.zone_name).await?;
        let removed = db.remove_pc_from_zone(zone_id, &req.pc_uuid).await?;
        let (ty, msg) = if removed > 0 {
            (chm_grpc::common::ResponseType::Ok as i32, "PC removed from zone".to_string())
        } else {
            (chm_grpc::common::ResponseType::Err as i32, "PC not found in zone".to_string())
        };
        Ok(Response::new(ResponseResult { r#type: ty, message: msg }))
    }

    async fn list_pcs_in_zone(
        &self,
        request: Request<ZoneIdentifier>,
    ) -> Result<Response<PcList>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone_id = db.get_zone_id(&req.zone_name).await?;
        let pcs = db.list_pcs_in_zone(zone_id).await?;
        Ok(Response::new(PcList { pcs }))
    }

    async fn list_zones_by_pc(
        &self,
        request: Request<PcIdentifier>,
    ) -> Result<Response<ZoneList>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zones = db.list_zones_by_pc(&req.pc_uuid).await?;
        let zones =
            zones.into_iter().map(|(_id, name, vni)| chm_grpc::dhcp::Zone { name, vni }).collect();
        Ok(Response::new(ZoneList { zones }))
    }

    async fn get_zone_detail_by_vni(
        &self,
        request: Request<VniIdentifier>,
    ) -> Result<Response<ZoneDetail>, Status> {
        let db = get_db().await;
        let vni = request.into_inner().vni;

        let info = db.get_zone_info_by_vni(vni).await?.ok_or_else(|| DhcpError::ZoneNotFound)?;

        let resp = ZoneDetail {
            name:        info.name,
            vni:         info.vni,
            network:     info.network,
            broadcast:   info.broadcast,
            subnet_mask: info.subnet_mask,
            ips:         info.ips,
            pcs:         info.pcs,
        };
        Ok(Response::new(resp))
    }

    async fn list_available_ips_by_vni(
        &self,
        request: Request<VniIdentifier>,
    ) -> Result<Response<IpList>, Status> {
        let db = get_db().await;
        let vni = request.into_inner().vni;
        let ips = db.get_ips_by_vni(vni).await?;
        Ok(Response::new(IpList { ips }))
    }

    async fn add_pc_to_zone_by_vni(
        &self,
        request: Request<AddPcToZoneByVniRequest>,
    ) -> Result<Response<ResponseResult>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone_id = db.get_zone_id_by_vni(req.vni).await?;
        let inserted = db.add_pc_to_zone(zone_id, &req.pc_uuid, true).await?;
        let (ty, msg) = if inserted {
            (chm_grpc::common::ResponseType::Ok as i32, "PC added to zone".to_string())
        } else {
            (chm_grpc::common::ResponseType::Ok as i32, "PC already in zone".to_string())
        };
        Ok(Response::new(ResponseResult { r#type: ty, message: msg }))
    }

    async fn remove_pc_from_zone_by_vni(
        &self,
        request: Request<RemovePcFromZoneByVniRequest>,
    ) -> Result<Response<ResponseResult>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        let zone_id = db.get_zone_id_by_vni(req.vni).await?;
        let affected = db.remove_pc_from_zone(zone_id, &req.pc_uuid).await?;
        let (ty, msg) = if affected > 0 {
            (chm_grpc::common::ResponseType::Ok as i32, "PC removed from zone".to_string())
        } else {
            (chm_grpc::common::ResponseType::Err as i32, "PC not found in zone".to_string())
        };
        Ok(Response::new(ResponseResult { r#type: ty, message: msg }))
    }

    async fn list_pcs_in_zone_by_vni(
        &self,
        request: Request<VniIdentifier>,
    ) -> Result<Response<PcList>, Status> {
        let db = get_db().await;
        let vni = request.into_inner().vni;
        let pcs = db.list_pcs_by_vni(vni).await?;
        Ok(Response::new(PcList { pcs }))
    }

    async fn update_zone_name_by_vni(
        &self,
        request: Request<UpdateZoneNameByVniRequest>,
    ) -> Result<Response<ResponseResult>, Status> {
        let db = get_db().await;
        let req = request.into_inner();
        if !db.zone_exists_by_vni(req.vni).await? {
            return Ok(Response::new(ResponseResult {
                r#type:  chm_grpc::common::ResponseType::Err as i32,
                message: format!("zone not found for vni={}", req.vni),
            }));
        }
        let affected = db.update_zone_name_by_vni(req.vni, &req.new_name).await;
        match affected {
            Ok(n) if n > 0 => Ok(Response::new(ResponseResult {
                r#type:  chm_grpc::common::ResponseType::Ok as i32,
                message: "Zone name updated".into(),
            })),
            Ok(_) => Ok(Response::new(ResponseResult {
                r#type:  chm_grpc::common::ResponseType::Err as i32,
                message: "No zone updated (maybe same name or not found)".into(),
            })),
            Err(DhcpError::ZoneExists(name)) => Ok(Response::new(ResponseResult {
                r#type:  chm_grpc::common::ResponseType::Err as i32,
                message: format!("zone name '{name}' already exists"),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}
