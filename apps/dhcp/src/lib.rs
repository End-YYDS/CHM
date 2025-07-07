use ipnetwork::IpNetwork;
use serde_json;
use sqlx::{FromRow, SqlitePool};
use std::net::IpAddr;
use thiserror::Error;
use tonic::{Request, Response, Status};

pub mod dhcp {
    include!("generated/dhcp.rs");
}

#[derive(Debug, Error)]
pub enum DhcpError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Invalid CIDR format")]
    InvalidCidr,

    #[error("Zone '{0}' already exists")]
    ZoneExists(String),

    #[error("Zone not found")]
    ZoneNotFound,

    #[error("No available IPs")]
    NoAvailableIps,

    #[error("IP conflict detected: {0:?}")]
    IpConflict(Vec<String>),

    #[error("Invalid IP address format: {0}")]
    InvalidIpFormat(String),
}

impl From<DhcpError> for Status {
    fn from(err: DhcpError) -> Self {
        match err {
            DhcpError::DatabaseError(e) => Status::internal(e.to_string()),
            DhcpError::InvalidCidr => Status::invalid_argument("Invalid CIDR format"),
            DhcpError::ZoneExists(z) => {
                Status::already_exists(format!("Zone '{}' already exists", z))
            }
            DhcpError::ZoneNotFound => Status::not_found("Zone not found"),
            DhcpError::NoAvailableIps => Status::resource_exhausted("No IP available"),
            DhcpError::IpConflict(conflicts) => {
                Status::already_exists(format!("IP conflict detected: {:?}", conflicts))
            }
            DhcpError::InvalidIpFormat(ip) => {
                Status::invalid_argument(format!("Invalid IP address format: {}", ip))
            }
        }
    }
}

#[derive(Debug, FromRow)]
struct Zone {
    id: i64,
    name: String,
    vni: i64,
    network: String,
    broadcast: String,
    subnet_mask: String,
}

#[derive(Debug, FromRow)]
struct IpPool {
    id: i64,
    zone_id: i64,
    ip: String,
}

#[derive(Debug, Default)]
pub struct DhcpServiceImpl {
    pub pool: Option<SqlitePool>,
}

#[tonic::async_trait]
impl dhcp::dhcp_service_server::DhcpService for DhcpServiceImpl {
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
        request: Request<dhcp::CreateZoneRequest>,
    ) -> Result<Response<dhcp::CreateZoneResponse>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();
        
        // Check if the zone already exists
        let exists = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_optional(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;
        if exists.is_some() {
            return Err(DhcpError::ZoneExists(req.zone_name).into());
        }
        
        // Parse CIDR
        let network = req
            .cidr
            .parse::<IpNetwork>()
            .map_err(|_| DhcpError::InvalidCidr)?;
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
        let ip_list_json = serde_json::to_string(&ip_list)
            .map_err(|_| DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let existing_conflicts = sqlx::query!(
            "SELECT ip FROM ip_pools WHERE ip IN (SELECT value FROM json_each(?))",
            ip_list_json
        )
        .fetch_all(pool)
        .await
        .map_err(DhcpError::DatabaseError)?;

        if !existing_conflicts.is_empty() {
            let conflicts = existing_conflicts.into_iter().map(|r| r.ip).collect();
            return Err(DhcpError::IpConflict(conflicts).into());
        }

        // insert zone
        let zone = Zone {
            id: 0,
            name: req.zone_name.clone(),
            vni: req.vni as i64,
            network: network.to_string(),
            broadcast: broadcast.clone(),
            subnet_mask: subnet_mask.clone(),
        };

        let result = sqlx::query!(
            "INSERT INTO zones (name, vni, network, broadcast, subnet_mask) VALUES (?, ?, ?, ?, ?)",
            zone.name,
            zone.vni,
            zone.network,
            zone.broadcast,
            zone.subnet_mask
        )
        .execute(pool)
        .await
        .map_err(DhcpError::DatabaseError)?;

        let zone_id = result.last_insert_rowid();

        // insert ip_pool
        for ip in network
            .iter()
            .filter(|ip| *ip != network.network() && *ip != network.broadcast())
        {
            let ip_pool = IpPool {
                id: 0,
                zone_id,
                ip: ip.to_string(),
            };

            sqlx::query!(
                "INSERT INTO ip_pools (zone_id, ip) VALUES (?, ?)",
                ip_pool.zone_id,
                ip_pool.ip
            )
            .execute(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;
        }

        Ok(Response::new(dhcp::CreateZoneResponse {
            message: "Zone created successfully".into(),
        }))
    }

    /// 刪除指定的 DHCP Zone
    /// # 參數
    /// * `request` - DeleteZoneRequest
    ///   - `group_name`: 所屬群組名稱
    ///   - `zone_name`: 欲刪除的 Zone 名稱
    /// 
    /// # 回傳
    /// * `Result<Response<DeleteZoneResponse>, Status>`  
    ///   成功時返回刪除成功訊息；失敗時返回 gRPC 錯誤狀態
    async fn delete_zone(
        &self,
        request: Request<dhcp::DeleteZoneRequest>,
    ) -> Result<Response<dhcp::DeleteZoneResponse>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();

        let exists = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_optional(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;
        if exists.is_none() {
            return Err(DhcpError::ZoneNotFound.into());
        }

        sqlx::query!("DELETE FROM zones WHERE name = ?", req.zone_name)
            .execute(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;

        Ok(Response::new(dhcp::DeleteZoneResponse {
            message: "Zone deleted".into(),
        }))
    }

    /// 從指定的 Zone 分配一個可用的 IP
    /// # 參數
    /// * `request` - AllocateIpRequest
    ///   - `zone_name`: 欲分配 IP 的 Zone 名稱
    /// 
    /// # 回傳
    /// * `Result<Response<AllocateIpResponse>, Status>`  
    ///   成功時返回分配的 IP；失敗時返回 gRPC 錯誤狀態
    async fn allocate_ip(
        &self,
        request: Request<dhcp::AllocateIpRequest>,
    ) -> Result<Response<dhcp::AllocateIpResponse>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();

        let zone = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_one(pool)
            .await
            .map_err(|_| DhcpError::ZoneNotFound)?;

        let ip: Option<IpPool> = sqlx::query_as_unchecked!(
            IpPool,
            "SELECT id, zone_id, ip FROM ip_pools WHERE zone_id = ? LIMIT 1",
            zone.id
        )
        .fetch_optional(pool)
        .await
        .map_err(DhcpError::DatabaseError)?;

        if let Some(ip_rec) = ip {
            sqlx::query!("DELETE FROM ip_pools WHERE id = ?", ip_rec.id)
                .execute(pool)
                .await
                .map_err(DhcpError::DatabaseError)?;

            Ok(Response::new(dhcp::AllocateIpResponse { ip: ip_rec.ip }))
        } else {
            Err(DhcpError::NoAvailableIps.into())
        }
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
        request: Request<dhcp::ReleaseIpRequest>,
    ) -> Result<Response<dhcp::ReleaseIpResponse>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();

        let zone = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_one(pool)
            .await
            .map_err(|_| DhcpError::ZoneNotFound)?;
        
        // Check if the IP is valid
        req.ip
            .parse::<IpAddr>()
            .map_err(|_| DhcpError::InvalidIpFormat(req.ip.clone()))?;

        sqlx::query!(
            "INSERT OR IGNORE INTO ip_pools (zone_id, ip) VALUES (?, ?)",
            zone.id,
            req.ip
        )
        .execute(pool)
        .await
        .map_err(DhcpError::DatabaseError)?;

        Ok(Response::new(dhcp::ReleaseIpResponse {
            message: "IP released".into(),
        }))
    }

    /// 列出所有已建立的 DHCP Zones
    /// # 參數
    /// * `_request` - Empty (無任何欄位)
    /// 
    /// # 回傳
    /// * `Result<Response<ZoneList>, Status>`  
    ///   成功時返回 Zone 列表；失敗時返回 gRPC 錯誤狀態
    async fn list_zones(
        &self,
        _request: Request<dhcp::Empty>,
    ) -> Result<Response<dhcp::ZoneList>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;

        let records = sqlx::query!("SELECT name, vni FROM zones")
            .fetch_all(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;

        let zones = records
            .into_iter()
            .map(|r| dhcp::Zone {
                name: r.name,
                vni: r.vni as i32,
            })
            .collect();

        Ok(Response::new(dhcp::ZoneList { zones }))
    }

    /// 列出指定 Zone 目前可用的所有 IP
    /// # 參數
    /// * `request` - ZoneIdentifier
    ///   - `zone_name`: 欲查詢的 Zone 名稱
    /// 
    /// # 回傳
    /// * `Result<Response<IpList>, Status>`  
    ///   成功時返回可用 IP 列表；失敗時返回 gRPC 錯誤狀態
    async fn list_available_ips(
        &self,
        request: Request<dhcp::ZoneIdentifier>,
    ) -> Result<Response<dhcp::IpList>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();

        let zone = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_one(pool)
            .await
            .map_err(|_| DhcpError::ZoneNotFound)?;

        let records = sqlx::query!("SELECT ip FROM ip_pools WHERE zone_id = ?", zone.id)
            .fetch_all(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;

        let ips = records.into_iter().map(|r| r.ip).collect();

        Ok(Response::new(dhcp::IpList { ips }))
    }
}
