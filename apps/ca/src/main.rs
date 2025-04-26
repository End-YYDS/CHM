mod functions;
pub(crate) mod grpc;
use std::fs;

use config::get_config_manager;
use functions::Certificate;
use openssl::x509::X509Req;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let args = args.get(1).unwrap();
    dbg!(args);
    let cmg = get_config_manager(None);
    dbg!(cmg);
    let ca_passwd = rpassword::prompt_password("Enter CA passphrase: ")?;
    let cert = Certificate::load(cmg.get_rootca_path(), cmg.get_rootca_key_path(), ca_passwd)?;
    dbg!(cert.get_ca_cert());
    let csr = X509Req::from_pem(&fs::read(args)?)?;
    let out_cert = cert.sign_csr(&csr, 365)?;
    dbg!(out_cert);
    Ok(())
}
