use chm_config_bus::_reexports::Uuid;
use sqlx::Error as SqlxError;
use std::env;
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum DnsSolverError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqlxError),

    #[error("Migration error: {0}")]
    MigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Invalid IP address format")]
    InvalidIpFormat,

    #[error("Environment variable DATABASE_URL is not set")]
    MissingDatabaseUrl(#[from] env::VarError),

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
            DnsSolverError::MigrationError(_) => Status::internal(e.to_string()),
            DnsSolverError::InvalidIpFormat => Status::invalid_argument(e.to_string()),
            DnsSolverError::MissingDatabaseUrl(_) => Status::internal(e.to_string()),
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
