use crate::cert::process::CertificateProcess;
use crate::config::is_debug;
use crate::globals::GlobalConfig;
use crate::{CaResult, PrivateKey, SignedCert};
use actix_tls::accept::openssl::TlsStream;
use actix_web::rt::net::TcpStream;
use actix_web::HttpRequest;
use actix_web::{dev::ServerHandle, post, web, App, HttpResponse, HttpServer};
use openssl::ssl::SslVerifyMode;
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod},
    x509::X509,
};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::sync::mpsc::Sender;
#[derive(Debug, Clone)]
pub struct PeerCerts(Vec<X509>);
#[derive(Debug)]
/// MiniController 用於管理初始化過程的控制器
pub struct MiniController {
    /// 伺服器自己的已簽署憑證
    sign_cert: Option<SignedCert>,
    /// 伺服器自己的私鑰
    private_key: Option<PrivateKey>,
    /// 伺服器的 handle
    server_handle: Option<ServerHandle>,
    /// 用於關閉伺服器的通道
    shutdown_tx: Option<Sender<()>>,
}
impl MiniController {
    /// 建立一個新的 MiniController
    /// # 參數
    /// * `sign_cert`: 可選的已簽署憑證
    /// * `private_key`: 可選的私鑰
    /// # 回傳
    /// * 一個新的 `MiniController` 實例
    pub fn new(sign_cert: Option<SignedCert>, private_key: Option<PrivateKey>) -> Self {
        Self {
            sign_cert,
            private_key,
            server_handle: None,
            shutdown_tx: None,
        }
    }
    /// 回傳伺服器X509憑證
    /// # 回傳
    /// * X509憑證
    pub fn get_cert(&self) -> Option<SignedCert> {
        self.sign_cert.clone()
    }

    /// 顯示伺服器憑證的內容
    /// # 回傳
    /// * `CaResult<String>`: 返回憑證的 PEM 格式字符串或錯誤
    pub fn show_cert(&self) -> CaResult<String> {
        let r = X509::from_der(self.sign_cert.as_ref().unwrap())?;
        let r = r.to_pem()?;
        let ret = String::from_utf8(r)?;
        Ok(ret)
    }

    /// 儲存伺服器憑證到指定的檔案
    /// # 參數
    /// * `filename`: 檔案名稱
    /// # 回傳
    /// * `CaResult<()>`: 返回結果，成功時為 Ok，失敗時為 Err
    pub fn save_cert(&self, filename: &str) -> CaResult<()> {
        let file_path = Path::new("certs").join(filename);
        let mut f = fs::File::create(file_path)?;
        f.write_all(self.show_cert()?.as_bytes())?;
        Ok(())
    }
    /// 啟動MiniController伺服器
    /// # 參數
    /// * `addr`: 伺服器的 Socket 地址
    /// * `marker_path`: 用於標記初始化完成的檔案路徑
    /// # 回傳
    /// * `CaResult<()>`: 返回結果，成功時為 Ok，失敗時為 Err
    pub async fn start(&mut self, addr: SocketAddr, marker_path: PathBuf) -> CaResult<()> {
        println!("Init Process Running on {} ...", addr);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let rootca = {
            if GlobalConfig::has_active_readers() {
                eprintln!("⚠️ 还有读锁没释放！2");
            }
            let cfg = GlobalConfig::read().await;
            cfg.settings.certificate.rootca.clone()
        };
        let ssl_acceptor = self
            .build_ssl_builder(&rootca)
            .map_err(|e| format!("SSL 建構失敗: {}", e))?;
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(marker_path.clone()))
                .app_data(web::Data::new(tx_clone.clone()))
                .service(init_api)
        })
        .on_connect(|conn, ext| {
            if let Some(stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
                let ssl_ref = stream.ssl();
                if let Some(cert) = ssl_ref.peer_certificate() {
                    ext.insert(PeerCerts(vec![cert]));
                }
            }
            // if let Some(stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
            //     let certs = stream.ssl().certificate();
            //     if let Some(certs) = certs {
            //         let certs = certs.to_owned();
            //         ext.insert(PeerCerts(certs));
            //     }
            // }
            // if let Some(stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
            //     println!("🛠 downcast 成功！");
            //     // 看看握手时到底有没有 peer cert
            //     let ssl = stream.ssl();
            //     match ssl.peer_certificate() {
            //         Some(cert) => {
            //             println!("🛠 peer_certificate subject: {:?}", cert.subject_name());
            //             ext.insert(PeerCerts(vec![cert.clone()]));
            //         }
            //         None => println!("🛠 没有 peer_certificate"),
            //     }
            // } else {
            //     println!("🛠 conn 不是 TlsStream<TcpStream>");
            // }
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
    /// 停止伺服器
    /// # 回傳
    /// * `CaResult<()>`: 返回結果，成功時為 Ok，失敗時為 Err
    pub fn stop(&self) -> CaResult<()> {
        if let Some(tx) = &self.shutdown_tx {
            tx.try_send(()).map_err(|e| e.into())
        } else {
            Ok(())
        }
    }
    /// 建立 SSL 接受器建構器
    /// # 回傳
    /// * `CaResult<SslAcceptorBuilder>`: 返回 SSL 接受器建構器或錯誤
    fn build_ssl_builder(&self, rootca: &str) -> CaResult<SslAcceptorBuilder> {
        let cert_bytes = self.sign_cert.as_ref().ok_or("missing certificate PEM")?;
        let key_bytes = self.private_key.as_ref().ok_or("missing private key PEM")?;
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        let cert = X509::from_pem(cert_bytes)
            .or_else(|_| X509::from_der(cert_bytes))
            .map_err(|e| format!("解析Leaf失敗: {}", e))?;
        builder.set_certificate(&cert)?;
        builder
            .set_ca_file(rootca)
            .map_err(|e| format!("設置CA檔案失敗: {}", e))?;

        // let mut store_builder = X509StoreBuilder::new().expect("創建X509StoreBuilder失敗");
        // store_builder.add_cert(cert).expect("添加憑證到X509StoreBuilder失敗");
        // let store = store_builder.build();
        // builder.set_verify_cert_store(store).expect("設置憑證存儲失敗");
        let pkey = PKey::private_key_from_pem(key_bytes)
            .or_else(|_| PKey::private_key_from_der(key_bytes))
            .map_err(|e| format!("解析PrivateKey失敗: {}", e))?;
        builder.set_private_key(&pkey)?;
        builder.check_private_key()?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        Ok(builder)
    }
}

#[post("init")]
/// 初始化 API，寫入 marker 檔案並關閉伺服器
/// # 參數
/// * `shutdown_tx`: 用於關閉伺服器的通道
/// * `marker_path`: 用於標記初始化完成的檔案路徑
/// # 回傳
/// * `HttpResponse`: 返回 HTTP 響應，成功時為 Ok，失敗時為 InternalServerError
async fn init_api(
    req: HttpRequest,
    shutdown_tx: web::Data<tokio::sync::mpsc::Sender<()>>,
    marker_path: web::Data<PathBuf>,
) -> HttpResponse {
    if let Some(peer) = req.conn_data::<PeerCerts>() {
        if is_debug() {
            dbg!(&peer.0);
        }
        let serial = peer
            .0
            .first()
            .and_then(|cert| CertificateProcess::cert_serial_sha256(cert).ok());
        let fingerprint = peer
            .0
            .first()
            .and_then(|cert| CertificateProcess::cert_fingerprint_sha256(cert).ok());

        if serial.is_some() && fingerprint.is_some() {
            {
                if GlobalConfig::has_active_readers() {
                    eprintln!("還有讀鎖沒釋放!-3");
                }
                let mut global = GlobalConfig::write().await;
                if let Some(s) = serial {
                    global.settings.controller.serial = s.clone();
                }
                if let Some(f) = fingerprint {
                    global.settings.controller.fingerprint = f.clone();
                }
            }
            if let Err(e) = GlobalConfig::save_config().await {
                eprintln!("儲存設定失敗: {}", e);
                return HttpResponse::InternalServerError().body("儲存設定失敗");
            }
        }
    } else {
        eprintln!("沒有找到 PeerCerts");
    }
    if let Err(e) = tokio::fs::write(marker_path.get_ref(), b"done").await {
        eprint!("寫入marker檔案失敗: {}", e);
        return HttpResponse::InternalServerError().body("寫入marker檔案失敗");
    }
    if is_debug() {
        println!("初始化完成，關閉伺服器");
    }

    let _ = shutdown_tx.send(()).await;
    HttpResponse::Ok().body("初始化完成")
}
