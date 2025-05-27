use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use ca::*;
use config::get_config_manager;
use openssl::x509::X509Req;
#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let marker_path = PathBuf::from("first_run.done");
    let first_run = !marker_path.exists();
    let cmg = get_config_manager(None);
    let ca_passwd = rpassword::prompt_password("Enter CA passphrase: ")?;
    let addr = cmg.get_grpc_service_ip("ca").parse()?;
    let cert_handler = Arc::new(Certificate::load(
        cmg.get_rootca_path(),
        cmg.get_rootca_key_path(),
        ca_passwd,
    )?);
    if first_run {
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
        let mut mini_c = mini_controller::MiniController::new(Some(mini_sign.0), Some(mini_cert.0));
        mini_c.save_cert("mini_controller.pem")?;
        mini_c
            .start(addr, marker_path.clone())
            .await
            .expect("啟動Web服務失敗");
    }
    start_grpc(addr, cert_handler).await?;
    Ok(())
}
