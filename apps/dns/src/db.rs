use crate::{error::DnsSolverError, GlobalConfig};
use chm_project_const::uuid::Uuid;
use sqlx::{types::ipnetwork::IpNetwork, PgPool};
use std::{env, net::IpAddr};

pub struct DnsSolver {
    pool: PgPool,
}

impl DnsSolver {
    pub async fn new() -> Result<Self, DnsSolverError> {
        let db_info = GlobalConfig::with(|cfg| cfg.extend.db_info.clone());
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| db_info.get_connection_string());
        let pool = PgPool::connect(&database_url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn add_host(
        &self,
        hostname: &str,
        ip: IpNetwork,
        id: Uuid,
    ) -> Result<(), DnsSolverError> {
        let existing = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(hostname.to_string()));
        }
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
