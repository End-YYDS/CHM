use dhcp::dhcp_service_server::{DhcpService, DhcpServiceServer};
use dhcp::{
    AllocateIpRequest, AllocateIpResponse, CreateZoneRequest, CreateZoneResponse,
    DeleteZoneRequest, DeleteZoneResponse, Empty, IpList, ReleaseIpRequest, ReleaseIpResponse,
    ZoneIdentifier, ZoneList,
};
use dotenv::dotenv;
use ipnetwork::IpNetwork;
use sqlx::{FromRow, SqlitePool};
use std::env;
use std::net::IpAddr;
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};
use serde_json;
use tokio::sync::watch;

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
    pool: Option<SqlitePool>,
}

#[tonic::async_trait]
impl DhcpService for DhcpServiceImpl {
    async fn create_zone(
        &self,
        request: Request<CreateZoneRequest>,
    ) -> Result<Response<CreateZoneResponse>, Status> {
        let pool = self
            .pool
            .as_ref()
            .ok_or(DhcpError::DatabaseError(sqlx::Error::RowNotFound))?;
        let req = request.into_inner();

        // check if the zone already exists
        let exists = sqlx::query!("SELECT id FROM zones WHERE name = ?", req.zone_name)
            .fetch_optional(pool)
            .await
            .map_err(DhcpError::DatabaseError)?;
        if exists.is_some() {
            return Err(DhcpError::ZoneExists(req.zone_name).into());
        }

        // parse CIDR
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

        // check IP conflict
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

        Ok(Response::new(CreateZoneResponse {
            message: "Zone created successfully".into(),
        }))
    }

    async fn delete_zone(
        &self,
        request: Request<DeleteZoneRequest>,
    ) -> Result<Response<DeleteZoneResponse>, Status> {
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

        Ok(Response::new(DeleteZoneResponse {
            message: "Zone deleted".into(),
        }))
    }

    async fn allocate_ip(
        &self,
        request: Request<AllocateIpRequest>,
    ) -> Result<Response<AllocateIpResponse>, Status> {
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

            Ok(Response::new(AllocateIpResponse { ip: ip_rec.ip }))
        } else {
            Err(DhcpError::NoAvailableIps.into())
        }
    }

    async fn release_ip(
        &self,
        request: Request<ReleaseIpRequest>,
    ) -> Result<Response<ReleaseIpResponse>, Status> {
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
        req.ip.parse::<IpAddr>().map_err(|_| DhcpError::InvalidIpFormat(req.ip.clone()))?;

        sqlx::query!(
            "INSERT OR IGNORE INTO ip_pools (zone_id, ip) VALUES (?, ?)",
            zone.id,
            req.ip
        )
        .execute(pool)
        .await
        .map_err(DhcpError::DatabaseError)?;

        Ok(Response::new(ReleaseIpResponse {
            message: "IP released".into(),
        }))
    }

    async fn list_zones(&self, _request: Request<Empty>) -> Result<Response<ZoneList>, Status> {
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

        Ok(Response::new(ZoneList { zones }))
    }

    async fn list_available_ips(
        &self,
        request: Request<ZoneIdentifier>,
    ) -> Result<Response<IpList>, Status> {
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

        Ok(Response::new(IpList { ips }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").unwrap_or("sqlite://dhcp.db".to_string());
    let pool = SqlitePool::connect(&db_url).await?;
    let addr = "[::1]:50051".parse()?;
    let (reload_tx, mut reload_rx) = watch::channel(());

    loop {
        let mut rx = reload_rx.clone();
        let service = DhcpServiceImpl { pool: Some(pool.clone()) };

        println!("[gRPC] server listening on {}", addr);

        let shutdown_signal = async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("[gRPC] shutting down...");
                }
                Ok(_) = rx.changed() => {
                    println!("[gRPC] restarting...");
                }
            }
        };

        let server = Server::builder()
            .add_service(DhcpServiceServer::new(service))
            .serve_with_shutdown(addr, shutdown_signal);

        if let Err(e) = server.await {
            eprintln!("[gRPC] startup failed: {:?}", e);
        }

        if reload_rx.has_changed().unwrap_or(false) {
            println!("[gRPC] restart complete");
            let _ = reload_rx.borrow_and_update();
            continue;
        }

        break;
    }

    Ok(())
}
