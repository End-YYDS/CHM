use dns::dns_service_server::{DnsService, DnsServiceServer};
use dns::{
    AddHostRequest, AddHostResponse, DeleteHostRequest, DeleteHostResponse, EditHostnameRequest,
    EditIpRequest, EditResponse, EditUuidRequest, GetHostnameByIpRequest, GetHostnameByUuidRequest,
    GetIpByHostnameRequest, GetIpByUuidRequest, GetUuidByHostnameRequest, GetUuidByIpRequest,
    HostnameResponse, IpResponse, UuidResponse,
};
use dotenv::dotenv;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::{Error as SqlxError, PgPool};
use std::env;
use std::net::IpAddr;
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

pub mod dns {
    include!("generated/dns.rs");
}

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
                Status::already_exists(format!("'{}' already exists", h))
            }
            DnsSolverError::NotFoundUuid(id) => {
                Status::not_found(format!("No entry found for UUID {}", id))
            }
            DnsSolverError::NotFoundHostname(h) => {
                Status::not_found(format!("No entry found for hostname {}", h))
            }
            DnsSolverError::NotFoundIp(ip) => {
                Status::not_found(format!("No entry found for IP {}", ip))
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
        dotenv().ok();
        let database_url =
            env::var("DATABASE_URL").map_err(|_| DnsSolverError::MissingDatabaseUrl)?;
        let pool = PgPool::connect(&database_url).await?;
        Ok(Self { pool })
    }

    pub async fn add_host(&self, hostname: &str, ip: IpNetwork) -> Result<Uuid, DnsSolverError> {
        // Check if the hostname already exists
        let existing = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1", hostname)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(hostname.to_string()));
        }

        let id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO hosts (id, hostname, ip) VALUES ($1, $2, $3)",
            id,
            hostname,
            ip
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<(), DnsSolverError> {
        sqlx::query!("DELETE FROM hosts WHERE id = $1", id)
            .execute(&self.pool)
            .await?;
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
        let existing = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1", new_hostname)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_hostname.to_string()));
        }

        sqlx::query!(
            "UPDATE hosts SET hostname = $1 WHERE id = $2",
            new_hostname,
            id
        )
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
        let row = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id)
            .ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
    }

    pub async fn get_uuid_by_ip(&self, ip: IpNetwork) -> Result<Uuid, DnsSolverError> {
        let row = sqlx::query!("SELECT id FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id)
            .ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_hostname_by_uuid(&self, id: Uuid) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname)
            .ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_hostname_by_ip(&self, ip: IpNetwork) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname)
            .ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_ip_by_uuid(&self, id: Uuid) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.ip.ip())
            .ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_ip_by_hostname(&self, hostname: &str) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE hostname = $1", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.ip.ip())
            .ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
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
        let ip: IpNetwork = req
            .ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.add_host(&req.hostname, ip).await {
            Ok(id) => Ok(Response::new(AddHostResponse { id: id.to_string() })),
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
        let ip: IpNetwork = req
            .new_ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP format"))?;

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
            Ok(uuid) => Ok(Response::new(UuidResponse {
                id: uuid.to_string(),
            })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_uuid_by_ip(
        &self,
        request: Request<GetUuidByIpRequest>,
    ) -> Result<Response<UuidResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork = req
            .ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.get_uuid_by_ip(ip).await {
            Ok(uuid) => Ok(Response::new(UuidResponse {
                id: uuid.to_string(),
            })),
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
        let ip: IpNetwork = req
            .ip
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid IP format"))?;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let solver = DnsSolver::new().await?;
    let service = MyDnsService::new(solver);

    println!("Starting gRPC server on {}", addr);
    Server::builder()
        .add_service(DnsServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
