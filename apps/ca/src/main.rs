use ca::{
    config::{config, NEED_EXAMPLE},
    crl::CrlVerifier,
    mini_controller::{MiniController, MiniResult},
    *,
};
use openssl::x509::{X509Req, X509};
use std::sync::atomic::Ordering::Relaxed;
use std::{env, fs, io::Write, net::SocketAddr, path::Path, sync::Arc};
#[actix_web::main]
async fn main() -> CaResult<()> {
    let args: Vec<String> = env::args().collect();
    let identity = ("com", "example", "chm");
    if args.iter().any(|a| a == "--init-config") {
        NEED_EXAMPLE.store(true, Relaxed);
        let _ = config(identity);
        return Ok(());
    }
    let (cmg, project_dir) = config(identity)?;
    let marker_path = Path::new(project_dir.data_dir()).join("first_run.done");
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let first_run = !marker_path.exists();
    // let ca_passwd = rpassword::prompt_password("Enter CA passphrase: ")?;
    let ca_passwd = cmg.certificate.passphrase;
    let addr = SocketAddr::new(cmg.server.host.parse()?, cmg.server.port);
    let cert_handler = Arc::new(Certificate::load(
        cmg.certificate.rootca,
        cmg.certificate.rootca_key,
        ca_passwd,
    )?);
    let client_cert = X509::from_pem(&fs::read("certs/grpc_test.pem")?)?;
    cert_handler.get_crl().mut_crl().add_revoked_cert(
        &client_cert,
        "".into(),
        CrlVerifier::get_utc(),
    )?;
    cert_handler
        .get_crl()
        .mut_crl()
        .save_to_file("certs/crl.toml")?;
    if first_run {
        let mut mini_c = mini_controller_cert(&cert_handler)?;
        ca_grpc_cert(&cert_handler)?;
        mini_c.start(addr, marker_path.clone()).await?;
    }
    if marker_path.exists() {
        start_grpc(addr, cert_handler.clone()).await?;
    }
    // grpc_test_cert(&cert_handler)?;
    Ok(())
}

fn mini_controller_cert(cert_handler: &Certificate) -> MiniResult<MiniController> {
    // 產生mini controller 的初始憑證,並將私鑰保存至certs資料夾內
    let mini_cert: (PrivateKey, CsrCert) = Certificate::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "miniC.example.com",
        &["127.0.0.1"],
    )?;
    let key = Path::new("certs").join("mini_controller.key");
    let mut f = fs::File::create(key)?;
    f.write_all(mini_cert.0.as_slice())?;
    let mini_csr = X509Req::from_pem(&mini_cert.1)?;
    let mini_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&mini_csr, 365)?;
    let mini_c = mini_controller::MiniController::new(Some(mini_sign.0), Some(mini_cert.0));
    mini_c.save_cert("mini_controller.pem")?;
    Ok(mini_c)
}

fn ca_grpc_cert(cert_handler: &Certificate) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = Certificate::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "ca.example.com",
        &["127.0.0.1"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365)?;
    Certificate::save_cert("ca_grpc", ca_grpc_sign.0, ca_grpc.0)?;
    Ok(())
}
#[allow(unused)]
fn grpc_test_cert(cert_handler: &Certificate) -> CaResult<()> {
    // 產生CA grpc的憑證,並將私鑰保存至certs資料夾內
    let ca_grpc: (PrivateKey, CsrCert) = Certificate::generate_csr(
        4096,
        "TW",
        "Taipei",
        "Taipei",
        "CHM Organization",
        "ca.example.com",
        &["127.0.0.1"],
    )?;
    let ca_grpc_csr = X509Req::from_pem(&ca_grpc.1)?;
    let ca_grpc_sign: (SignedCert, ChainCerts) = cert_handler.sign_csr(&ca_grpc_csr, 365)?;
    Certificate::save_cert("grpc_test", ca_grpc_sign.0, ca_grpc.0)?;
    Ok(())
}
