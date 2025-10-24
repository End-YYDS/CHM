use crate::{
    config::{config, CertInfo},
    globals::GlobalConfig,
};
use argh::FromArgs;
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{
    api_resp, atomic_write, declare_init_route, BootstrapResp, Default_ServerCluster, InitData,
    ServiceDescriptor, ServiceKind,
    _reexports::{Data, HttpRequest, HttpResponse, Json},
};
use chm_config_bus::{declare_config, declare_config_bus};
use chm_grpc::{
    dns::{
        dns_service_server::{DnsService, DnsServiceServer},
        AddHostRequest, AddHostResponse, DeleteHostRequest, DeleteHostResponse,
        EditHostnameRequest, EditIpRequest, EditResponse, EditUuidRequest, GetHostnameByIpRequest,
        GetHostnameByUuidRequest, GetIpByHostnameRequest, GetIpByUuidRequest,
        GetUuidByHostnameRequest, GetUuidByIpRequest, HostnameResponse, IpResponse, UuidResponse,
    },
    tonic_health::server::health_reporter,
};
use chm_project_const::{uuid::Uuid, ProjectConst};
use http::Request as hRequest;
use serde::{Deserialize, Serialize};
use sqlx::{
    types::ipnetwork::{IpNetwork, Ipv4Network},
    Error as SqlxError, PgPool,
};
#[cfg(debug_assertions)]
use std::net::Ipv4Addr;
use std::{
    env,
    net::{IpAddr, SocketAddrV4},
    ops::ControlFlow,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::watch;
use tonic::{
    codec::CompressionEncoding,
    codegen::InterceptedService,
    transport::{Certificate, Identity, ServerTlsConfig},
    Request, Response, Status,
};
use tower::{Layer, Service};
use tracing_subscriber::EnvFilter;

pub static NEED_EXAMPLE: AtomicBool = AtomicBool::new(false);
pub const ID: &str = "CHMmDNS";
#[cfg(debug_assertions)]
pub const DEFAULT_PORT: u16 = 50053;
pub const DEFAULT_OTP_LEN: usize = 6;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;
pub const DEFAULT_TIMEOUT: u64 = 10;
pub const DEFAULT_BITS: i32 = 256;
pub const DEFAULT_CRL_UPDATE_INTERVAL: u64 = 3600; // 1 小時

#[derive(Debug, FromArgs)]
/// DNS 主程式參數
pub struct Cli {
    /// 範例配置檔案
    #[argh(switch, short = 'i')]
    init_config: bool,
}

#[derive(Debug)]
pub struct InitCarry {
    pub root_ca_path:    PathBuf,
    pub uuid:            Uuid,
    pub server_hostname: String,
    pub server_addr:     SocketAddrV4,
    pub private_key:     Vec<u8>,
    pub cert_info:       CertInfo,
}

impl InitCarry {
    pub fn new(
        root_ca_path: PathBuf,
        uuid: Uuid,
        server_hostname: String,
        server_addr: SocketAddrV4,
        private_key: Vec<u8>,
        cert_info: CertInfo,
    ) -> Arc<Self> {
        Arc::new(Self { root_ca_path, uuid, server_hostname, server_addr, private_key, cert_info })
    }
}
async fn init_data_handler(
    _req: &HttpRequest,
    Json(data): Json<InitData>,
    carry: Data<Arc<InitCarry>>,
) -> ControlFlow<HttpResponse, ()> {
    match data {
        InitData::Bootstrap { root_ca_pem, .. } => {
            if let Err(e) = atomic_write(&carry.root_ca_path, &root_ca_pem).await {
                tracing::error!("寫入 RootCA 憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "寫入 RootCA 憑證失敗"));
            }
            let mut san_extend = carry.cert_info.san.clone();
            san_extend.push(carry.uuid.to_string());
            let csr_pem = match CertUtils::generate_csr(
                carry.private_key.clone(),
                &carry.cert_info.country,
                &carry.cert_info.state,
                &carry.cert_info.locality,
                ProjectConst::PROJECT_NAME,
                format!("{}.chm.com", &carry.cert_info.cn).as_str(),
                san_extend,
            ) {
                Ok(csr) => csr,
                Err(e) => {
                    tracing::error!("生成 CSR 失敗: {:?}", e);
                    return ControlFlow::Break(api_resp!(InternalServerError "生成 CSR 失敗"));
                }
            };

            let service_desp = ServiceDescriptor {
                kind:        ServiceKind::Dns,
                uri:         format!("https://{}:{}", carry.uuid, carry.server_addr.port()),
                health_name: Some("dns.DnsService".to_string()),
                is_server:   true,
                hostname:    ID.to_string(),
                uuid:        carry.uuid,
            };
            let resp = BootstrapResp { csr_pem, socket: carry.server_addr, service_desp };
            return ControlFlow::Break(api_resp!(ok "初始化交換成功", resp));
        }
        InitData::Finalize { id, cert_pem, controller_pem, controller_uuid, .. } => {
            if id != carry.uuid {
                tracing::warn!("收到的 UUID 與預期不符，拒絕接收憑證");
                return ControlFlow::Break(api_resp!(BadRequest "UUID 不符"));
            }
            if let Err(e) = CertUtils::save_cert(ID, &carry.private_key, &cert_pem) {
                tracing::error!("保存憑證失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "保存憑證失敗"));
            }
            GlobalConfig::update_with(|cfg| {
                let cert =
                    CertUtils::load_cert_from_bytes(&controller_pem).expect("無法載入剛接收的憑證");
                cfg.extend.controller.serial =
                    CertUtils::cert_serial_sha256(&cert).expect("無法計算Serial");
                cfg.extend.controller.fingerprint = CertUtils::cert_fingerprint_sha256(&cert)
                    .expect(
                        "
            無法計算fingerprint",
                    );
                cfg.extend.controller.uuid = controller_uuid;
            });
            if let Err(e) = GlobalConfig::save_config().await {
                tracing::error!("保存配置檔案失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "保存配置檔案失敗"));
            }
            if let Err(e) = GlobalConfig::reload_config().await {
                tracing::error!("重新載入配置檔案失敗: {:?}", e);
                return ControlFlow::Break(api_resp!(InternalServerError "重新載入配置檔案失敗"));
            }
            tracing::info!("初始化完成，已接收憑證");
        }
    }
    ControlFlow::Continue(())
}
declare_init_route!(init_data_handler, data = InitData, extras = (carry: Arc<InitCarry>));

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DnsExtension {
    #[serde(default)]
    pub db_info:    DnsDb,
    #[serde(default)]
    pub controller: Controller,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DnsDb {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub host:     String,
    #[serde(default)]
    pub port:     u16,
    #[serde(default)]
    pub dbname:   String,
}

impl Default for DnsDb {
    fn default() -> Self {
        Self {
            username: "chm".into(),
            password: "".into(),
            host:     IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
            port:     5432,
            dbname:   "dns".into(),
        }
    }
}

impl DnsDb {
    pub fn get_connection_string(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.dbname
        )
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
/// 控制器設定
pub struct Controller {
    /// 控制器的指紋，用於識別和驗證
    #[serde(default = "Controller::default_fingerprint")]
    pub fingerprint: String,
    /// 控制器的序列號，用於唯一標識
    #[serde(default = "Controller::default_serial")]
    pub serial:      String,
    /// 控制器的UUID
    #[serde(default = "Controller::default_uuid")]
    pub uuid:        Uuid,
}

impl Controller {
    /// 取得控制器的預設指紋
    pub fn default_fingerprint() -> String {
        "".into()
    }
    /// 取得控制器的預設序列號
    pub fn default_serial() -> String {
        "".into()
    }
    pub fn default_uuid() -> Uuid {
        Uuid::nil()
    }
}
declare_config!(extend = crate::DnsExtension);
declare_config_bus!();
#[derive(Debug, Error)]
pub enum DnsSolverError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] SqlxError),

    #[error("Migration error: {0}")]
    MigrationError(#[from] sqlx::migrate::MigrateError),

    #[error("Invalid IP address format")]
    InvalidIpFormat,

    #[error("Environment variable DATABASE_URL is not set")]
    MissingDatabaseUrl(#[from] env::VarError),

    #[error("'{0}' already exists")]
    AlreadyExists(String),

    #[error("No entry found for UUID {0}")]
    NotFoundUuid(Uuid),

    #[error("No entry found for hostname {0}")]
    NotFoundHostname(String),

    #[error("No entry found for IP {0}")]
    NotFoundIp(String),

    #[error("Failed to edit entry")]
    EditError,
}

impl From<DnsSolverError> for Status {
    fn from(e: DnsSolverError) -> Self {
        match e {
            DnsSolverError::DatabaseError(_) => Status::internal(e.to_string()),
            DnsSolverError::MigrationError(_) => Status::internal(e.to_string()),
            DnsSolverError::InvalidIpFormat => Status::invalid_argument(e.to_string()),
            DnsSolverError::MissingDatabaseUrl(_) => Status::internal(e.to_string()),
            DnsSolverError::AlreadyExists(h) => {
                Status::already_exists(format!("'{h}' already exists"))
            }
            DnsSolverError::NotFoundUuid(id) => {
                Status::not_found(format!("No entry found for UUID {id}"))
            }
            DnsSolverError::NotFoundHostname(h) => {
                Status::not_found(format!("No entry found for hostname {h}"))
            }
            DnsSolverError::NotFoundIp(ip) => {
                Status::not_found(format!("No entry found for IP {ip}"))
            }
            DnsSolverError::EditError => Status::internal(e.to_string()),
        }
    }
}

pub struct DnsSolver {
    pool: PgPool,
}

impl DnsSolver {
    pub async fn new() -> Result<Self, DnsSolverError> {
        let db_info = GlobalConfig::with(|cfg| cfg.extend.db_info.clone());
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| db_info.get_connection_string());
        let pool = PgPool::connect(&database_url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn add_host(
        &self,
        hostname: &str,
        ip: IpNetwork,
        id: Uuid,
    ) -> Result<(), DnsSolverError> {
        let existing = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(hostname.to_string()));
        }
        sqlx::query!("INSERT INTO hosts (id, hostname, ip) VALUES ($1, $2, $3)", id, hostname, ip)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<(), DnsSolverError> {
        sqlx::query!("DELETE FROM hosts WHERE id = $1", id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn edit_uuid(&self, id: Uuid, new_id: Uuid) -> Result<(), DnsSolverError> {
        let existing = sqlx::query!("SELECT id FROM hosts WHERE id = $1", new_id)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_id.to_string()));
        }

        sqlx::query!("UPDATE hosts SET id = $1 WHERE id = $2", new_id, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn edit_hostname(&self, id: Uuid, new_hostname: &str) -> Result<(), DnsSolverError> {
        let existing =
            sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", new_hostname)
                .fetch_optional(&self.pool)
                .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_hostname.to_string()));
        }

        sqlx::query!("UPDATE hosts SET hostname = $1 WHERE id = $2", new_hostname, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn edit_ip(&self, id: Uuid, new_ip: IpNetwork) -> Result<(), DnsSolverError> {
        let existing = sqlx::query!("SELECT id FROM hosts WHERE ip = $1", new_ip)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Err(DnsSolverError::AlreadyExists(new_ip.to_string()));
        }

        sqlx::query!("UPDATE hosts SET ip = $1 WHERE id = $2", new_ip, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_uuid_by_hostname(&self, hostname: &str) -> Result<Uuid, DnsSolverError> {
        let row = sqlx::query!("SELECT id FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id).ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
    }

    pub async fn get_uuid_by_ip(&self, ip: IpNetwork) -> Result<Uuid, DnsSolverError> {
        let row = sqlx::query!("SELECT id FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.id).ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_hostname_by_uuid(&self, id: Uuid) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname).ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_hostname_by_ip(&self, ip: IpNetwork) -> Result<String, DnsSolverError> {
        let row = sqlx::query!("SELECT hostname FROM hosts WHERE ip = $1", ip)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.hostname).ok_or(DnsSolverError::NotFoundIp(ip.to_string()))
    }

    pub async fn get_ip_by_uuid(&self, id: Uuid) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.ip.ip()).ok_or(DnsSolverError::NotFoundUuid(id))
    }

    pub async fn get_ip_by_hostname(&self, hostname: &str) -> Result<IpAddr, DnsSolverError> {
        let row = sqlx::query!("SELECT ip FROM hosts WHERE hostname = $1::citext", hostname)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.ip.ip()).ok_or(DnsSolverError::NotFoundHostname(hostname.to_string()))
    }
}

#[allow(dead_code)]
pub struct MyDnsService {
    solver:   DnsSolver,
    reloader: watch::Sender<()>,
}

impl MyDnsService {
    pub fn new(solver: DnsSolver, reloader: watch::Sender<()>) -> Self {
        Self { solver, reloader }
    }
}

#[tonic::async_trait]
impl DnsService for MyDnsService {
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;
        let id: Uuid =
            req.id.parse().map_err(|_| Status::invalid_argument("Invalid UUID format"))?;

        match self.solver.add_host(&req.hostname, ip, id).await {
            Ok(_) => Ok(Response::new(AddHostResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.delete_host(id).await {
            Ok(_) => Ok(Response::new(DeleteHostResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_uuid(
        &self,
        request: Request<EditUuidRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        let new_id =
            Uuid::parse_str(&req.new_id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.edit_uuid(id, new_id).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_hostname(
        &self,
        request: Request<EditHostnameRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.edit_hostname(id, &req.new_hostname).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn edit_ip(
        &self,
        request: Request<EditIpRequest>,
    ) -> Result<Response<EditResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;
        let ip: IpNetwork =
            req.new_ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.edit_ip(id, ip).await {
            Ok(_) => Ok(Response::new(EditResponse { success: true })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_uuid_by_hostname(
        &self,
        request: Request<GetUuidByHostnameRequest>,
    ) -> Result<Response<UuidResponse>, Status> {
        let req = request.into_inner();
        match self.solver.get_uuid_by_hostname(&req.hostname).await {
            Ok(uuid) => Ok(Response::new(UuidResponse { id: uuid.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_uuid_by_ip(
        &self,
        request: Request<GetUuidByIpRequest>,
    ) -> Result<Response<UuidResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.get_uuid_by_ip(ip).await {
            Ok(uuid) => Ok(Response::new(UuidResponse { id: uuid.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_hostname_by_uuid(
        &self,
        request: Request<GetHostnameByUuidRequest>,
    ) -> Result<Response<HostnameResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.get_hostname_by_uuid(id).await {
            Ok(hostname) => Ok(Response::new(HostnameResponse { hostname })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_hostname_by_ip(
        &self,
        request: Request<GetHostnameByIpRequest>,
    ) -> Result<Response<HostnameResponse>, Status> {
        let req = request.into_inner();
        let ip: IpNetwork =
            req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP format"))?;

        match self.solver.get_hostname_by_ip(ip).await {
            Ok(hostname) => Ok(Response::new(HostnameResponse { hostname })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_ip_by_uuid(
        &self,
        request: Request<GetIpByUuidRequest>,
    ) -> Result<Response<IpResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid UUID"))?;

        match self.solver.get_ip_by_uuid(id).await {
            Ok(ip) => Ok(Response::new(IpResponse { ip: ip.to_string() })),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_ip_by_hostname(
        &self,
        request: Request<GetIpByHostnameRequest>,
    ) -> Result<Response<IpResponse>, Status> {
        let req = request.into_inner();

        match self.solver.get_ip_by_hostname(&req.hostname).await {
            Ok(ip) => Ok(Response::new(IpResponse { ip: ip.to_string() })),
            Err(e) => Err(e.into()),
        }
    }
}
#[derive(Clone, Debug)]
pub struct GrpcRouteInfo {
    pub path:    String,
    pub service: String,
    pub method:  String,
}

#[derive(Clone, Default)]
pub struct GrpcRouteLayer;

impl<S> Layer<S> for GrpcRouteLayer {
    type Service = GrpcRouteSvc<S>;
    fn layer(&self, inner: S) -> Self::Service {
        GrpcRouteSvc { inner }
    }
}

#[derive(Clone)]
pub struct GrpcRouteSvc<S> {
    inner: S,
}

impl<S, B> Service<hRequest<B>> for GrpcRouteSvc<S>
where
    S: Service<hRequest<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hRequest<B>) -> Self::Future {
        let path = req.uri().path().to_string();
        let (service, method) = if let Some(rest) = path.strip_prefix('/') {
            let mut it = rest.splitn(2, '/');
            (it.next().unwrap_or_default().to_string(), it.next().unwrap_or_default().to_string())
        } else {
            (String::new(), String::new())
        };

        req.extensions_mut().insert(GrpcRouteInfo { path, service, method });
        self.inner.call(req)
    }
}
fn make_dns_interceptor<F>(
    controller_args: (String, String),
    needs_controller: F,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static
where
    F: Fn(&GrpcRouteInfo) -> bool + Clone + Send + Sync + 'static,
{
    move |req: Request<()>| {
        let m = req
            .extensions()
            .get::<GrpcRouteInfo>()
            .ok_or_else(|| Status::internal("GrpcRouteInfo missing after routing"))?;
        if !needs_controller(m) {
            return Ok(req);
        }
        let peer_der_vec =
            req.peer_certs().ok_or_else(|| Status::unauthenticated("No TLS connection"))?;
        let leaf = peer_der_vec
            .as_ref()
            .as_slice()
            .first()
            .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;

        let x509 = CertUtils::load_cert_from_bytes(leaf)
            .map_err(|_| Status::invalid_argument("Peer certificate DER is invalid"))?;
        let serial = CertUtils::cert_serial_sha256(&x509)
            .map_err(|e| Status::internal(format!("Serial sha256 failed: {e}")))?;
        let fingerprint = CertUtils::cert_fingerprint_sha256(&x509)
            .map_err(|e| Status::internal(format!("Fingerprint sha256 failed: {e}")))?;

        if serial != controller_args.0 || fingerprint != controller_args.1 {
            return Err(Status::permission_denied("Only controller cert is allowed"));
        }

        Ok(req)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Cli = argh::from_env();
    #[cfg(debug_assertions)]
    let filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    #[cfg(not(debug_assertions))]
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if args.init_config {
        NEED_EXAMPLE.store(true, Relaxed);
        tracing::info!("初始化配置檔案...");
        config().await?;
        tracing::info!("配置檔案已生成，請檢查 {ID}_config.toml.example");
        return Ok(());
    }
    config().await?;
    let (hostname, addr, rootca, cert_info, otp_len, otp_time, self_uuid, key_path, cert_path) =
        GlobalConfig::with(|cfg| {
            let hostname = cfg.server.hostname.clone();
            let host: Ipv4Addr = cfg.server.host.clone().parse().unwrap_or(Ipv4Addr::LOCALHOST);
            let port = cfg.server.port;
            let rootca = cfg.certificate.root_ca.clone();
            let cert_info = cfg.certificate.cert_info.clone();
            let otp_len = cfg.server.otp_len;
            let otp_time = cfg.server.otp_time;
            let uuid = cfg.server.unique_id;
            let key_path = cfg.certificate.client_key.clone();
            let cert_path = cfg.certificate.client_cert.clone();
            (
                hostname,
                SocketAddrV4::new(host, port),
                rootca,
                cert_info,
                otp_len,
                otp_time,
                uuid,
                key_path,
                cert_path,
            )
        });
    let (key, x509_cert) = CertUtils::generate_self_signed_cert(
        cert_info.bits,
        &cert_info.country,
        &cert_info.state,
        &cert_info.locality,
        &cert_info.org,
        &cert_info.cn,
        &cert_info.san,
        cert_info.days,
    )
    .map_err(|e| format!("生成自簽憑證失敗: {e}"))?;
    let carry = InitCarry::new(
        rootca.clone(),
        self_uuid,
        ID.to_string(),
        addr,
        key.clone(),
        cert_info.clone(),
    );
    let init_server =
        Default_ServerCluster::new(addr.to_string(), x509_cert, key, None::<String>, otp_len, ID)
            .with_otp_rotate_every(otp_time)
            .add_configurer(init_route())
            .with_app_data::<InitCarry>(carry.clone());
    tracing::info!("啟動初始化 Server，等待 Controller 的初始化請求...");
    match init_server.init().await {
        ControlFlow::Continue(()) => {
            tracing::info!("初始化完成，啟動正式服務...");
        }
        ControlFlow::Break(_) => {
            tracing::warn!("初始化未完成 (Ctrl+C)，程式結束");
            return Ok(());
        }
    }
    tracing::info!("初始化 Server 已結束，繼續啟動正式服務...");
    tracing::info!("正在啟動DNS...");
    let (cert_update_tx, mut cert_update_rx) = watch::channel(());
    loop {
        let (key, cert) = CertUtils::cert_from_path(&cert_path, &key_path, None)?;
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(Certificate::from_pem(CertUtils::load_cert(&rootca)?.to_pem()?));
        let (health_reporter, health_service) = health_reporter();
        health_reporter.set_serving::<DnsServiceServer<MyDnsService>>().await;
        let mut rx = cert_update_rx.clone();
        let shutdown_signal = {
            let health_reporter = health_reporter.clone();
            async move {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("[gRPC] 收到 Ctrl-C，開始關閉...");
                    }
                    Ok(_) = rx.changed() => {
                        tracing::info!("[gRPC] 憑證更新，開始重新啟動 gRPC...");
                    }
                }
                health_reporter.set_not_serving::<DnsServiceServer<MyDnsService>>().await;
            }
        };
        let controller_args = GlobalConfig::with(|cfg| {
            (cfg.extend.controller.serial.clone(), cfg.extend.controller.fingerprint.clone())
        });
        let solver = DnsSolver::new().await?;
        let full_fqdn = format!("{hostname}.chm.com");
        let ip_net = Ipv4Network::new(*addr.ip(), 32)?;
        if solver.add_host(&full_fqdn, ip_net.into(), self_uuid).await.is_err() {
            let dns_uuid = solver.get_uuid_by_hostname(&full_fqdn).await?;
            if let Err(e) = solver.edit_ip(dns_uuid, ip_net.into()).await {
                tracing::warn!("DNS主機IP更新失敗: {}", e);
            }
        }
        let needs = |m: &GrpcRouteInfo| {
            m.service.as_str() == "dns.DnsService"
                && matches!(
                    m.method.as_str(),
                    "AddHost" | "DeleteHost" | "EditUuid" | "EditHostname" | "EditIp"
                )
        };
        let raw_dns = DnsServiceServer::new(MyDnsService::new(solver, cert_update_tx.clone()))
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd);
        let dns_svc =
            InterceptedService::new(raw_dns, make_dns_interceptor(controller_args, needs));
        tracing::info!("Starting gRPC server on {addr}");
        let server = chm_cluster_utils::gserver::grpc_with_tuning()
            .tls_config(tls)?
            .layer(GrpcRouteLayer)
            .add_service(dns_svc)
            .add_service(health_service)
            .serve_with_shutdown(addr.into(), shutdown_signal);
        if let Err(e) = server.await {
            tracing::error!("[gRPC] 啟動失敗: {e:?}");
        }
        if cert_update_rx.has_changed().unwrap_or(false) {
            tracing::info!("[gRPC] 憑證更新，重新啟動 gRPC 服務");
            let _ = cert_update_rx.borrow_and_update();
            continue;
        }
        break;
    }
    // TODO: 添加CRL檢查
    Ok(())
}
