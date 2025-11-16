#[derive(thiserror::Error, Debug)]
pub enum VxlanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("Invalid CIDR format")]
    InvalidCidr,

    #[error("Invalid IPv4 address: {0}")]
    InvalidIpv4(String),

    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),

    #[error("Interface `{0}` not found")]
    InterfaceNotFound(String),

    #[error("No default route found")]
    NoDefaultRoute,
}
