use crate::db::DnsSolver;
use chm_cert_utils::CertUtils;
use chm_config_bus::_reexports::Uuid;
use chm_grpc::dns::{
    dns_service_server::DnsService, AddHostRequest, AddHostResponse, DeleteHostRequest,
    DeleteHostResponse, EditHostnameRequest, EditIpRequest, EditResponse, EditUuidRequest,
    GetHostnameByIpRequest, GetHostnameByUuidRequest, GetIpByHostnameRequest, GetIpByUuidRequest,
    GetUuidByHostnameRequest, GetUuidByIpRequest, HostnameResponse, IpResponse, UuidResponse,
};
use http::Request as hRequest;
use sqlx::types::ipnetwork::IpNetwork;
use std::task::{Context, Poll};
use tokio::sync::watch;
use tonic::{codegen::Service, Request, Response, Status};
use tower::Layer;

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

pub fn make_dns_interceptor<F>(
    controller_args: (String, String),
    needs_controller: F,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static
where
    F: Fn(&GrpcRouteInfo) -> bool + Clone + Send + Sync + 'static,
{
    move |req: Request<()>| {
        let m = req.extensions().get::<GrpcRouteInfo>().ok_or_else(|| {
            Status::internal(
                "GrpcRouteInfo missing after
routing",
            )
        })?;
        if !needs_controller(m) {
            return Ok(req);
        }
        let peer_der_vec = req.peer_certs().ok_or_else(|| {
            Status::unauthenticated(
                "No TLS
connection",
            )
        })?;
        let leaf = peer_der_vec.as_ref().as_slice().first().ok_or_else(|| {
            Status::unauthenticated(
                "No peer certificate
presented",
            )
        })?;

        let x509 = CertUtils::load_cert_from_bytes(leaf).map_err(|_| {
            Status::invalid_argument(
                "Peer certificate DER is
invalid",
            )
        })?;
        let serial = CertUtils::cert_serial_sha256(&x509).map_err(|e| {
            Status::internal(format!(
                "Serial sha256 failed:
{e}"
            ))
        })?;
        let fingerprint = CertUtils::cert_fingerprint_sha256(&x509).map_err(|e| {
            Status::internal(format!(
                "Fingerprint sha256 failed:
{e}"
            ))
        })?;

        if serial != controller_args.0 || fingerprint != controller_args.1 {
            return Err(Status::permission_denied(
                "Only controller cert is
allowed",
            ));
        }

        Ok(req)
    }
}
