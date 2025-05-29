use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::{PrivateKey, SignedCert};
use actix_web::{dev::ServerHandle, post, web, App, HttpResponse, HttpServer};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod},
    x509::X509,
};
use tokio::sync::mpsc::Sender;
pub type MiniResult<T> = Result<T, Box<dyn std::error::Error>>;
#[derive(Debug)]
pub struct MiniController {
    sign_cert: Option<SignedCert>,
    private_key: Option<PrivateKey>,
    server_handle: Option<ServerHandle>,
    shutdown_tx: Option<Sender<()>>,
}
impl MiniController {
    pub fn new(sign_cert: Option<SignedCert>, private_key: Option<PrivateKey>) -> Self {
        Self {
            sign_cert,
            private_key,
            server_handle: None,
            shutdown_tx: None,
        }
    }

    pub fn get_cert(&self) -> bool {
        self.sign_cert.is_some()
    }
    pub fn show_cert(&self) -> MiniResult<String> {
        let r = X509::from_der(self.sign_cert.as_ref().unwrap())?;
        let r = r.to_pem()?;
        let ret = String::from_utf8(r)?;
        Ok(ret)
    }
    pub fn save_cert(&self, filename: &str) -> MiniResult<()> {
        let file_path = Path::new("certs").join(filename);
        let mut f = fs::File::create(file_path)?;
        f.write_all(self.show_cert()?.as_bytes())?;
        Ok(())
    }
    pub async fn start(&mut self, addr: SocketAddr, marker_path: PathBuf) -> MiniResult<()> {
        println!("Init Process Running on {} ...", addr);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let ssl_acceptor = self
            .build_ssl_builder()
            .map_err(|e| format!("SSL 建構失敗: {}", e))?;
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(marker_path.clone()))
                .app_data(web::Data::new(tx_clone.clone()))
                .service(init_api)
        })
        .bind_openssl(addr, ssl_acceptor)?
        .disable_signals()
        .run();
        let handle = server.handle();
        self.server_handle = Some(handle.clone());
        self.shutdown_tx = Some(tx);
        let h = handle.clone();
        tokio::spawn(async move {
            if rx.recv().await.is_some() {
                h.stop(false).await;
            }
        });
        let h2 = handle.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("CtrlC Error");
            h2.stop(false).await;
        });
        server.await?;
        Ok(())
    }
    pub fn stop(&self) -> MiniResult<()> {
        if let Some(tx) = &self.shutdown_tx {
            tx.try_send(()).map_err(|e| e.into())
        } else {
            Ok(())
        }
    }
    fn build_ssl_builder(&self) -> MiniResult<SslAcceptorBuilder> {
        let cert_bytes = self.sign_cert.as_ref().ok_or("missing certificate PEM")?;
        let key_bytes = self.private_key.as_ref().ok_or("missing private key PEM")?;
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        let cert = X509::from_pem(cert_bytes)
            .or_else(|_| X509::from_der(cert_bytes))
            .map_err(|e| format!("解析Leaf失敗: {}", e))?;
        builder.set_certificate(&cert)?;
        let pkey = PKey::private_key_from_pem(key_bytes)
            .or_else(|_| PKey::private_key_from_der(key_bytes))
            .map_err(|e| format!("解析PrivateKey失敗: {}", e))?;
        builder.set_private_key(&pkey)?;
        builder.check_private_key()?;
        Ok(builder)
    }
}

#[post("init")]
async fn init_api(
    shutdown_tx: web::Data<tokio::sync::mpsc::Sender<()>>,
    marker_path: web::Data<PathBuf>,
) -> HttpResponse {
    if let Err(e) = tokio::fs::write(marker_path.get_ref(), b"done").await {
        eprint!("寫入marker檔案失敗: {}", e);
        return HttpResponse::InternalServerError().body("寫入marker檔案失敗");
    }
    let _ = shutdown_tx.send(()).await;
    HttpResponse::Ok().body("初始化完成")
}
