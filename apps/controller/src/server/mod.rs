use crate::ConResult;
use chm_cert_utils::CertUtils;
use std::net::SocketAddr;

pub mod restful;
#[allow(unused)]
pub async fn start_grpc(addr: SocketAddr) -> ConResult<()> {
    // Todo: 憑證重載機制
    let (key, cert) = CertUtils::cert_from_name("Controller", None)?;
    Ok(())
}
