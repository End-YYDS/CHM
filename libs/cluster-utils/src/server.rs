use actix_tls::accept::openssl::TlsStream;
use actix_web::{
    web::{Data, ServiceConfig},
    App, HttpServer,
};
use chm_project_const::ProjectConst;
use openssl::{
    error::ErrorStack,
    pkey::PKey,
    ssl::{SslAcceptorBuilder, SslFiletype, SslMethod, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use std::{
    fmt::Debug,
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, sync::RwLock, time, time::Instant};

pub type ValidCertHandler = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct PeerCerts(pub Vec<X509>);
pub type Configurer = Vec<Arc<dyn Fn(&mut ServiceConfig) + Send + Sync>>;
pub struct ServerCluster {
    bind_address:       String,
    cert:               Option<PemOrPath>,
    key:                Option<PemOrPath>,
    root_ca:            Option<PemOrPath>,
    otp:                Arc<RwLock<String>>,
    otp_len:            usize,
    ssl_acceptor:       Option<SslAcceptorBuilder>,
    custom_otp:         bool,
    marker_path:        Option<String>,
    valid_cert_handler: Option<ValidCertHandler>,
    configurers:        Configurer,
    otp_rotate_every:   Option<Duration>,
}
impl Debug for ServerCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCluster")
            .field("bind_address", &self.bind_address)
            .field("cert", &self.cert)
            .field("key", &self.key)
            .field("root_ca", &self.root_ca)
            .field("otp", &self.otp)
            .field("otp_len", &self.otp_len)
            .field("custom_otp", &self.custom_otp)
            .field("marker_path", &self.marker_path)
            .field("otp_rotate_every", &self.otp_rotate_every)
            .finish()
    }
}

impl Default for ServerCluster {
    fn default() -> Self {
        Self {
            bind_address:       "0.0.0.0:50051".into(),
            cert:               None,
            key:                None,
            root_ca:            None,
            otp:                Arc::new(RwLock::new(String::new())),
            otp_len:            6,
            ssl_acceptor:       None,
            custom_otp:         false,
            marker_path:        None,
            valid_cert_handler: None,
            configurers:        Vec::new(),
            otp_rotate_every:   None,
        }
    }
}
#[derive(Debug, Clone)]
pub enum PemOrPath {
    Path(PathBuf),
    Pem(Vec<u8>),
}

impl From<String> for PemOrPath {
    fn from(s: String) -> Self {
        Self::Path(PathBuf::from(s))
    }
}
impl From<&str> for PemOrPath {
    fn from(s: &str) -> Self {
        Self::Path(PathBuf::from(s))
    }
}
impl From<PathBuf> for PemOrPath {
    fn from(p: PathBuf) -> Self {
        Self::Path(p)
    }
}
impl From<&Path> for PemOrPath {
    fn from(p: &Path) -> Self {
        Self::Path(p.to_path_buf())
    }
}
impl From<Vec<u8>> for PemOrPath {
    fn from(b: Vec<u8>) -> Self {
        Self::Pem(b)
    }
}
impl From<&[u8]> for PemOrPath {
    fn from(b: &[u8]) -> Self {
        Self::Pem(b.to_vec())
    }
}

impl ServerCluster {
    pub fn new(
        addr: impl Into<String>,
        cert_path: impl Into<PemOrPath>,
        cert_key: impl Into<PemOrPath>,
        root_ca: Option<impl Into<PemOrPath>>,
        otp_len: usize,
        marker_path: impl Into<String>,
    ) -> Self {
        Self::default()
            .with_bind_addr(addr)
            .with_cert_chain(cert_path, cert_key)
            .with_root_ca(root_ca)
            .with_otp_len(otp_len)
            .with_otp()
            .with_marker_path(marker_path)
            .build_ssl_acceptor()
            .expect("Failed to build SSL acceptor")
    }
    pub fn with_app_data<T>(mut self, data: impl Into<Arc<T>>) -> Self
    where
        T: Send + Sync + 'static,
    {
        let data: Arc<T> = data.into();
        self.configurers.push(Arc::new(move |cfg: &mut ServiceConfig| {
            cfg.app_data(Data::new(data.clone()));
        }));
        self
    }
    pub fn with_valid_cert_handler<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.valid_cert_handler = Some(Arc::new(f));
        self
    }
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = addr.into();
        self
    }
    pub fn with_cert_chain(
        mut self,
        cert: impl Into<PemOrPath>,
        key: impl Into<PemOrPath>,
    ) -> Self {
        self.cert = Some(cert.into());
        self.key = Some(key.into());
        self
    }
    pub fn with_root_ca(mut self, ca: Option<impl Into<PemOrPath>>) -> Self {
        self.root_ca = ca.map(Into::into);
        self
    }
    pub fn with_otp_len(mut self, len: usize) -> Self {
        self.otp_len = len;
        self
    }
    pub fn with_otp(mut self) -> Self {
        self.otp = Arc::new(RwLock::new(chm_password::generate_otp(self.otp_len)));
        self
    }
    pub fn with_marker_path(mut self, path: impl Into<String>) -> Self {
        self.marker_path = Some(path.into());
        self
    }
    pub fn with_ssl_acceptor(mut self, acceptor: SslAcceptorBuilder) -> Self {
        self.ssl_acceptor = Some(acceptor);
        self
    }
    pub fn with_custom_otp(mut self, custom: bool, passwd: Option<impl Into<String>>) -> Self {
        self.custom_otp = custom;
        let first = if custom {
            passwd.map(Into::into).unwrap_or_else(|| chm_password::generate_otp(self.otp_len))
        } else {
            chm_password::generate_otp(self.otp_len)
        };
        self.otp = Arc::new(RwLock::new(first));
        self
    }
    pub fn add_configurer<F>(mut self, f: F) -> Self
    where
        F: Fn(&mut ServiceConfig) + Send + Sync + 'static,
    {
        self.configurers.push(Arc::new(f));
        self
    }
    pub fn with_otp_rotate_every(mut self, every: Duration) -> Self {
        self.otp_rotate_every = Some(every);
        self
    }
    pub fn make_ssl_acceptor_builder(&self) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        if let Some(ref key_src) = self.key {
            match key_src {
                PemOrPath::Path(p) => {
                    let p = ProjectConst::certs_path().join(p);
                    builder.set_private_key_file(p, SslFiletype::PEM)?;
                }
                PemOrPath::Pem(bytes) => {
                    let pkey = PKey::private_key_from_pem(bytes)?;
                    builder.set_private_key(&pkey)?;
                }
            }
        }
        if let Some(ref cert_src) = self.cert {
            match cert_src {
                PemOrPath::Path(p) => {
                    let p = ProjectConst::certs_path().join(p);
                    builder.set_certificate_file(p, SslFiletype::PEM)?;
                }
                PemOrPath::Pem(bytes) => {
                    let cert = X509::from_pem(bytes)?;
                    builder.set_certificate(&cert)?;
                }
            }
        }
        if let Some(ref ca_src) = self.root_ca {
            match ca_src {
                PemOrPath::Path(p) => {
                    builder.set_ca_file(p)?;
                }
                PemOrPath::Pem(bytes) => {
                    let cas = X509::stack_from_pem(bytes)?;
                    let mut store_builder = X509StoreBuilder::new()?;
                    for ca in cas {
                        store_builder.add_cert(ca)?;
                    }
                    builder.set_verify_cert_store(store_builder.build())?;
                }
            }
        }

        builder.check_private_key()?;
        builder.set_verify(SslVerifyMode::NONE);
        Ok(builder)
    }
    fn build_ssl_acceptor(mut self) -> Result<Self, ErrorStack> {
        let builder = self.make_ssl_acceptor_builder()?;
        self.ssl_acceptor = Some(builder);
        Ok(self)
    }
    pub async fn current_otp(&self) -> String {
        self.otp.read().await.clone()
    }
    pub async fn init(&self) -> ControlFlow<Box<dyn std::error::Error + Send + Sync>, ()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let bind_addr = self.bind_address.clone();
        let marker = self.marker_path.clone().expect("marker_path should have been set");
        let marker_path = ProjectConst::data_path().join(format!(".{marker}.done"));
        if marker_path.exists() {
            tracing::info!("已完成初始化，跳過初始化伺服器啟動");
            return ControlFlow::Continue(());
        }
        let ssl_builder = match self.make_ssl_acceptor_builder() {
            Ok(b) => b,
            Err(e) => return ControlFlow::Break(e.into()),
        };
        let valid_cb = self.valid_cert_handler.clone();
        let configurers = self.configurers.clone();
        let otp_store = self.otp.clone();
        let rotate_cfg = self.otp_rotate_every;
        tracing::info!("Starting server on {bind_addr}");
        tracing::info!("Using OTP: {}", self.current_otp().await);
        let server = match HttpServer::new(move || {
            let configurers = configurers.clone();
            let mut app = App::new()
                .app_data(Data::new(marker_path.clone()))
                .app_data(Data::new(otp_store.clone()))
                .app_data(Data::new(tx_clone.clone()));
            if let Some(ref cb) = valid_cb {
                app = app.app_data(Data::new(cb.clone()));
            }
            let cfgs = configurers.clone();
            app = app.configure(move |cfg| {
                for c in &cfgs {
                    c(cfg);
                }
            });
            app
        })
        .on_connect(|conn, ext| {
            if let Some(stream) = conn.downcast_ref::<TlsStream<TcpStream>>() {
                let ssl_ref = stream.ssl();
                if let Some(cert) = ssl_ref.peer_certificate() {
                    ext.insert(PeerCerts(vec![cert]));
                }
            }
        })
        .bind_openssl(bind_addr, ssl_builder)
        {
            Ok(b) => b.disable_signals().run(),
            Err(e) => return ControlFlow::Break(e.into()),
        };

        let handle = server.handle();
        let h_for_rx = handle.clone();
        let (otp_tx, mut otp_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            if rx.recv().await.is_some() {
                let _ = otp_tx.send(());
                h_for_rx.stop(false).await;
            }
        });
        let (abort_tx, mut abort_rx) = tokio::sync::oneshot::channel::<()>();
        let h_for_abort = handle.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("CtrlC Error: {e}");
            }
            let _ = abort_tx.send(());
        });
        if let Some(every) = rotate_cfg {
            let otp_store = self.otp.clone();
            let otp_len = self.otp_len;
            tokio::spawn(async move {
                let start = Instant::now() + every;
                let mut ticker = time::interval_at(start, every);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let new = chm_password::generate_otp(otp_len);
                            *otp_store.write().await = new.clone();
                            tracing::info!("(rotated) New OTP: {}", new);
                        }
                        _ = &mut otp_rx => {
                            tracing::info!("OTP rotation stopped");
                            break;
                        }
                    }
                }
            });
        }
        let flow = tokio::select! {
            res = server => {
                match res {
                    Ok(()) => ControlFlow::Continue(()),
                    Err(e)  => ControlFlow::Break(e.into()),
                }
            }
            _ = &mut abort_rx => {
                h_for_abort.stop(false).await;
                ControlFlow::Break("aborted by Ctrl-C".into())
            }
        };
        flow
    }
}
