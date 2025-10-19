use crate::{db::get_db, error::DhcpError, LZone};
use chm_grpc::{
    dhcp::{
        dhcp_service_server::DhcpService, AllocateIpRequest, AllocateIpResponse, CreateZoneRequest,
        CreateZoneResponse, DeleteZoneRequest, DeleteZoneResponse, Empty, IpList, ReleaseIpRequest,
        ReleaseIpResponse, ZoneIdentifier, ZoneList,
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
        // Check if the zone already exists
        let exists = db.is_zone_exist(&req.zone_name).await?;
        if exists {
            return Err(DhcpError::ZoneExists(req.zone_name).into());
        }
        // Parse CIDR
        let network = req.cidr.parse::<IpNetwork>().map_err(|_| DhcpError::InvalidCidr)?;
        let broadcast = network.broadcast().to_string();
        let subnet_mask = network.mask().to_string();
        let prefix = network.prefix();
        if (network.is_ipv4() && prefix > 30) || (network.is_ipv6() && prefix > 126) {
            return Err(DhcpError::InvalidCidr.into());
        }
        let ip_list: Vec<String> = network
            .iter()
            .filter(|ip| *ip != network.network() && *ip != network.broadcast())
            .map(|ip| ip.to_string())
            .collect();
        // Check for IP conflicts
        let ip_list_json = serde_json::to_string(&ip_list).map_err(DhcpError::JsonError)?;
        let (has, conflicts) = db.is_ip_conflict(ip_list_json).await?;
        if !has {
            return Err(DhcpError::IpConflict(conflicts).into());
        }
        // insert zone
        let zone = LZone {
            id:          0,
            name:        req.zone_name.clone(),
            vni:         req.vni as i64,
            network:     network.to_string(),
            broadcast:   broadcast.clone(),
            subnet_mask: subnet_mask.clone(),
        };
        let zone_id = db.insert_zone(zone).await?;
        // insert ip_pool
        for ip in network.iter().filter(|ip| *ip != network.network() && *ip != network.broadcast())
        {
            let ip_string = ip.to_string();
            db.insert_ip_pool(zone_id, ip_string, false).await?;
        }

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
}
