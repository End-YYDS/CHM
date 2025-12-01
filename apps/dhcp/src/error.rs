use chm_grpc::tonic::Status;
use sqlx::migrate::MigrateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DhcpError {
    #[error(transparent)]
    DatabaseError(#[from] sqlx::Error),

    #[error(transparent)]
    DbMigrate(#[from] MigrateError),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

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

    #[error("Unsupported IPv6 address")]
    UnsupportedIpv6,
}

impl From<DhcpError> for Status {
    fn from(err: DhcpError) -> Self {
        match err {
            DhcpError::InvalidCidr => Status::invalid_argument("Invalid CIDR format"),
            DhcpError::ZoneExists(z) => {
                Status::already_exists(format!("Zone '{z}' already exists"))
            }
            DhcpError::ZoneNotFound => Status::not_found("Zone not found"),
            DhcpError::NoAvailableIps => Status::resource_exhausted("No IP available"),
            DhcpError::IpConflict(conflicts) => {
                Status::already_exists(format!("IP conflict detected: {conflicts:?}"))
            }
            DhcpError::InvalidIpFormat(ip) => {
                Status::invalid_argument(format!("Invalid IP address format: {ip}"))
            }
            DhcpError::UnsupportedIpv6 => Status::invalid_argument("Unsupported IPv6 address"),
            _ => Status::internal(err.to_string()),
        }
    }
}
