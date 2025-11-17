use chm_grpc::tonic::Status;
use sqlx::migrate::MigrateError;
use thiserror::Error;

pub type SrvResult<T> = Result<T, LdapServiceError>;
#[derive(Debug, Error)]
pub enum LdapServiceError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    #[error(transparent)]
    DbMigrate(#[from] MigrateError),

    #[error(transparent)]
    Ldap(#[from] ldap3::LdapError),

    #[error("User '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("User '{0}' not found")]
    UserNotFound(String),

    #[error("Group '{0}' already exists")]
    GroupAlreadyExists(String),

    #[error("Group '{0}' not found")]
    GroupNotFound(String),

    #[error("LDAP operation error: {0}")]
    OperationError(String),

    #[error("Invalid credentials")]
    InvalidCredentials,
}

impl From<LdapServiceError> for Status {
    fn from(err: LdapServiceError) -> Self {
        match err {
            LdapServiceError::UserAlreadyExists(uid) => Status::already_exists(uid),
            LdapServiceError::UserNotFound(uid) => Status::not_found(uid),
            LdapServiceError::GroupAlreadyExists(g) => Status::already_exists(g),
            LdapServiceError::GroupNotFound(g) => Status::not_found(g),
            LdapServiceError::InvalidCredentials => Status::unauthenticated("Invalid credentials"),
            e => Status::internal(e.to_string()),
        }
    }
}
