use sqlx::{PgPool, Error as SqlxError};
use uuid::Uuid;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use dotenv::dotenv;
use std::env;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub hostname: String,
    pub ip: IpAddr,
}

#[derive(Debug, Error)]
pub enum DnsSolverError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqlxError),
    
    #[error("Invalid IP address format")]
    InvalidIpFormat,
    
    #[error("Environment variable DATABASE_URL is not set")]
    MissingDatabaseUrl,
}

pub struct DnsSolver {
    pool: PgPool,
}

impl DnsSolver {
    // 初始化連線
    pub async fn new() -> Result<Self, DnsSolverError> {
        dotenv().ok();
        let database_url = env::var("DATABASE_URL").map_err(|_| DnsSolverError::MissingDatabaseUrl)?;
        let pool = PgPool::connect(&database_url).await?;
        Ok(Self { pool })
    }

    // 新增主機
    pub async fn add_host(&self, hostname: &str, ip: IpAddr) -> Result<Uuid, DnsSolverError> {
        let id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO hosts (id, hostname, ip) VALUES ($1, $2, $3)",
            id,
            hostname,
            ip.to_string()
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    // 透過 UUID 查詢
    pub async fn get_host_by_uuid(&self, id: Uuid) -> Result<Host, DnsSolverError> {
        let row = sqlx::query!("SELECT id, hostname, ip FROM hosts WHERE id = $1", id)
            .fetch_one(&self.pool)
            .await?;
        let ip = row.ip.parse().map_err(|_| DnsSolverError::InvalidIpFormat)?;
        Ok(Host { id: row.id, hostname: row.hostname, ip })
    }

    // 透過 Hostname 查詢
    pub async fn get_host_by_hostname(&self, hostname: &str) -> Result<Host, DnsSolverError> {
        let row = sqlx::query!("SELECT id, hostname, ip FROM hosts WHERE hostname = $1", hostname)
            .fetch_one(&self.pool)
            .await?;
        let ip = row.ip.parse().map_err(|_| DnsSolverError::InvalidIpFormat)?;
        Ok(Host { id: row.id, hostname: row.hostname, ip })
    }

    // 透過 IP 查詢
    pub async fn get_host_by_ip(&self, ip: IpAddr) -> Result<Host, DnsSolverError> {
        let row = sqlx::query!("SELECT id, hostname, ip FROM hosts WHERE ip = $1", ip.to_string())
            .fetch_one(&self.pool)
            .await?;
        let ip = row.ip.parse().map_err(|_| DnsSolverError::InvalidIpFormat)?;
        Ok(Host { id: row.id, hostname: row.hostname, ip })
    }

    // 刪除主機
    pub async fn delete_host(&self, id: Uuid) -> Result<(), DnsSolverError> {
        sqlx::query!("DELETE FROM hosts WHERE id = $1", id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    match DnsSolver::new().await {
        Ok(solver) => {
            match solver.add_host("server1", "192.168.1.1".parse().unwrap()).await {
                Ok(id) => {
                    println!("Added host with ID: {}", id);
                    
                    match solver.get_host_by_uuid(id).await {
                        Ok(host) => println!("Found host by UUID: {:?}", host),
                        Err(e) => eprintln!("Error finding host by UUID: {}", e),
                    }

                    match solver.get_host_by_hostname("server1").await {
                        Ok(host) => println!("Found host by hostname: {:?}", host),
                        Err(e) => eprintln!("Error finding host by hostname: {}", e),
                    }
                    
                    match solver.get_host_by_ip("192.168.1.1".parse().unwrap()).await {
                        Ok(host) => println!("Found host by IP: {:?}", host),
                        Err(e) => eprintln!("Error finding host by IP: {}", e),
                    }
                    
                    match solver.delete_host(id).await {
                        Ok(_) => println!("Deleted host: {}", id),
                        Err(e) => eprintln!("Error deleting host: {}", e),
                    }
                },
                Err(e) => eprintln!("Error adding host: {}", e),
            }
        }
        Err(e) => eprintln!("Error initializing DnsSolver: {}", e),
    }
}