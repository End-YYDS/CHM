use chm_grpc::dns::{
    dns_service_server::{DnsService, DnsServiceServer},
    AddHostRequest, AddHostResponse, DeleteHostRequest, DeleteHostResponse, EditHostnameRequest,
    EditIpRequest, EditResponse, EditUuidRequest, GetHostnameByIpRequest, GetHostnameByUuidRequest,
    GetIpByHostnameRequest, GetIpByUuidRequest, GetUuidByHostnameRequest, GetUuidByIpRequest,
    HostnameResponse, IpResponse, UuidResponse,
};
use sqlx::{types::ipnetwork::IpNetwork, Error as SqlxError, PgPool};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DnsSolverError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqlxError),

    #[error("Invalid IP address format")]
    InvalidIpFormat,

    #[error("Environment variable DATABASE_URL is not set")]
    MissingDatabaseUrl,

    #[error("'{0}' already exists")]
    AlreadyExists(String),

    #[error("No entry found for UUID {0}")]
    NotFoundUuid(Uuid),

    #[error("No entry found for hostname {0}")]
    NotFoundHostname(String),

    #[error("No entry found for IP {0}")]
    NotFoundIp(String),

    #[error("Failed to edit entry")]
    EditError,
}

impl From<DnsSolverError> for Status {
    fn from(e: DnsSolverError) -> Self {
        match e {
            DnsSolverError::DatabaseError(_) => Status::internal(e.to_string()),
            DnsSolverError::InvalidIpFormat => Status::invalid_argument(e.to_string()),
            DnsSolverError::MissingDatabaseUrl => Status::internal(e.to_string()),
            DnsSolverError::AlreadyExists(h) => {
                Status::already_exists(format!("'{h}' already exists"))
            }
            DnsSolverError::NotFoundUuid(id) => {
                Status::not_found(format!("No entry found for UUID {id}"))
            }
            DnsSolverError::NotFoundHostname(h) => {
                Status::not_found(format!("No entry found for hostname {h}"))
            }
            DnsSolverError::NotFoundIp(ip) => {
                Status::not_found(format!("No entry found for IP {ip}"))
            }
            DnsSolverError::EditError => Status::internal(e.to_string()),
        }
    }
}

pub struct DnsSolver {
    pool: PgPool,
}

impl DnsSolver {
    pub async fn new() -> Result<Self, DnsSolverError> {
        // TODO: 從Config中讀取數據庫連接字符串
        let database_url =
            env::var("DATABASE_URL").map_err(|_| DnsSolverError::MissingDatabaseUrl)?;
        let pool = PgPool::connect(&database_url).await?;
        Ok(Self { pool })
    }

    pub async fn add_host(
        &self,
        hostname: &str,
        ip: IpNetwork,
        id: Uuid,
    ) -> Result<(), DnsSolverError> {
        // Check if the hostname already exists
        let existing = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(hostname.to_string()));
        }

        // let id = Uuid::new_v4();
        sqlx::query!("INSERT INTO hosts (id, hostname, ip) VALUES ($1, $2, $3)", id, hostname, ip)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<(), DnsSolverError> {
        sqlx::query!("DELETE FROM hosts WHERE id = $1", id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn edit_uuid(&self, id: Uuid, new_id: Uuid) -> Result<(), DnsSolverError> {
        // Check if the uuid already exists
        let existing = sqlx::query!("SELECT id FROM hosts WHERE id = $1", new_id)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_id.to_string()));
        }

        sqlx::query!("UPDATE hosts SET id = $1 WHERE id = $2", new_id, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn edit_hostname(&self, id: Uuid, new_hostname: &str) -> Result<(), DnsSolverError> {
        // Check if the hostname already exists
        let existing =
            sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", new_hostname)
                .fetch_optional(&self.pool)
                .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_hostname.to_string()));
        }

        sqlx::query!("UPDATE hosts SET hostname = $1 WHERE id = $2", new_hostname, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn edit_ip(&self, id: Uuid, new_ip: IpNetwork) -> Result<(), DnsSolverError> {
        // Check if the ip already exists
        let existing = sqlx::query!("SELECT id FROM hosts WHERE ip = $1", new_ip)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_ip.to_string()));
        }

        sqlx::query!("UPDATE hosts SET ip = $1 WHERE id = $2", new_ip, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_uuid_by_hostname(&self, hostname: &str) -> Result<Uuid, DnsSolverError> {
        let row = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id).ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
    }

    pub async fn get_uuid_by_ip(&self, ip: IpNetwork) -> Result<Uuid, DnsSolverError> {
        let row = sqlx::query!("SELECT id FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id).ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_hostname_by_uuid(&self, id: Uuid) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname).ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_hostname_by_ip(&self, ip: IpNetwork) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname).ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_ip_by_uuid(&self, id: Uuid) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.ip.ip()).ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_ip_by_hostname(&self, hostname: &str) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.ip.ip()).ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
    }
}

pub struct MyDnsService {
    solver: DnsSolver,
}

impl MyDnsService {
    pub fn new(solver: DnsSolver) -> Self {
        Self { solver }
    }
}

#[tonic::async_trait]
impl DnsService for MyDnsService {
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;
        let id: Uuid =
            req.id.parse().map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        match self.solver.add_host(&req.hostname, ip, id).await {
            Ok(_) => Ok(Response::new(AddHostResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.delete_host(id).await {
            Ok(_) => Ok(Response::new(DeleteHostResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_uuid(
        &self,
        request: Request<EditUuidRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        let new_id =
            Uuid::parse_str(&req.new_id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.edit_uuid(id, new_id).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_hostname(
        &self,
        request: Request<EditHostnameRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.edit_hostname(id, &req.new_hostname).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_ip(
        &self,
        request: Request<EditIpRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        let ip: IpNetwork =
            req.new_ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.edit_ip(id, ip).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_uuid_by_hostname(
        &self,
        request: Request<GetUuidByHostnameRequest>,
    ) -> Result<Response<UuidResponse>, Status> {
        let req = request.into_inner();
        match self.solver.get_uuid_by_hostname(&req.hostname).await {
            Ok(uuid) => Ok(Response::new(UuidResponse { id: uuid.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_uuid_by_ip(
        &self,
        request: Request<GetUuidByIpRequest>,
    ) -> Result<Response<UuidResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.get_uuid_by_ip(ip).await {
            Ok(uuid) => Ok(Response::new(UuidResponse { id: uuid.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_hostname_by_uuid(
        &self,
        request: Request<GetHostnameByUuidRequest>,
    ) -> Result<Response<HostnameResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.get_hostname_by_uuid(id).await {
            Ok(hostname) => Ok(Response::new(HostnameResponse { hostname })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_hostname_by_ip(
        &self,
        request: Request<GetHostnameByIpRequest>,
    ) -> Result<Response<HostnameResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.get_hostname_by_ip(ip).await {
            Ok(hostname) => Ok(Response::new(HostnameResponse { hostname })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_ip_by_uuid(
        &self,
        request: Request<GetIpByUuidRequest>,
    ) -> Result<Response<IpResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.get_ip_by_uuid(id).await {
            Ok(ip) => Ok(Response::new(IpResponse { ip: ip.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_ip_by_hostname(
        &self,
        request: Request<GetIpByHostnameRequest>,
    ) -> Result<Response<IpResponse>, Status> {
        let req = request.into_inner();

        match self.solver.get_ip_by_hostname(&req.hostname).await {
            Ok(ip) => Ok(Response::new(IpResponse { ip: ip.to_string() })),
            Err(e) => Err(e.into()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();
    tracing::info!("正在啟動DNS...");
    let local_ip = if cfg!(debug_assertions) {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        chm_dns_resolver::DnsResolver::get_local_ip()?
    };
    let addr: SocketAddr = format!("{local_ip}:50053").parse()?;
    let solver = DnsSolver::new().await?;
    // 手動添加默認mCA主機
    // if let Err(e) = solver.add_host("mdns.chm.com", addr.ip().into()).await {
    //     let dns_uuid = solver.get_uuid_by_hostname("mdns.chm.com").await?;
    //     if let Err(e) = solver.edit_ip(dns_uuid, local_ip.into()).await {
    //         tracing::warn!("Failed to edit default host IP: {}", e);
    //     }
    //     tracing::warn!("Failed to add default host: {}", e);
    // }
    let service = MyDnsService::new(solver);
    tracing::info!("Starting gRPC server on {addr}");
    Server::builder().add_service(DnsServiceServer::new(service)).serve(addr).await?;
    // TODO: 添加TLS支持,及添加CRL檢查
    // TODO: 配置添加至Controller中的服務

    Ok(())
}
