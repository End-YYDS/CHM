#![allow(dead_code, unused_variables)]

use crate::{communication::GrpcClients, ConResult, GlobalConfig, InfoThresholds, MetricThreshold};
use chm_cert_utils::CertUtils;
use chm_cluster_utils::{ServiceDescriptor, ServiceKind};
use chm_grpc::{
    agent::{
        self, command_response, AgentCommand, CommandRequest, GetInfoRequest as AgentGetInfoRequest,
    },
    common::{
        self, action_result, ActionResult, CommonInfo, Date, ErrorLog, LogLevel, Month,
        ResponseResult, ResponseType, Status as CommonStatus, Week,
    },
    restful::{self, restful_service_server::RestfulService, *},
    tonic,
    tonic::{Request, Response, Status},
    tonic_health::{
        pb::{health_client::HealthClient, HealthCheckRequest},
        ServingStatus,
    },
};
use chm_project_const::uuid::Uuid;
use futures::future::join_all;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::{sync::Semaphore, task::JoinSet};
use tracing::{debug, error, warn};

#[derive(Debug, Clone)]
struct AgentSnapshot {
    uuid: String,
    cpu:  f64,
    mem:  f64,
    disk: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum NodeStatus {
    Safe = 0,
    Warn = 1,
    Danger = 2,
}

impl ControllerRestfulServer {
    fn agent_descriptors(filter: Option<&Uuid>) -> Vec<ServiceDescriptor> {
        GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .get(&ServiceKind::Agent)
                .map(|entry| {
                    entry
                        .iter()
                        .filter(|desc| filter.is_none_or(|uuid| &desc.uuid == uuid))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    fn agent_exists(uuid: &Uuid) -> bool {
        GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .get(&ServiceKind::Agent)
                .map(|entry| entry.iter().any(|desc| &desc.uuid == uuid))
                .unwrap_or(false)
        })
    }

    async fn collect_agent_snapshots(&self, filter: Option<Uuid>) -> ConResult<Vec<AgentSnapshot>> {
        let descriptors = Self::agent_descriptors(filter.as_ref());
        if descriptors.is_empty() {
            return Ok(Vec::new());
        }

        let concurrency = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let permits = if concurrency == 0 { 1 } else { concurrency };
        let semaphore = Arc::new(Semaphore::new(permits));
        let mut set = JoinSet::new();

        for descriptor in descriptors {
            let clients = self.grpc_clients.clone();
            let semaphore = semaphore.clone();
            let agent_uuid = descriptor.uuid.to_string();

            set.spawn(async move {
                let permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| format!("Failed to acquire semaphore for agent {agent_uuid}"))?;

                let uuid_label = agent_uuid.clone();
                let snapshot = clients
                    .with_agent_uuid_handle(&agent_uuid, move |agent| {
                        let uuid_for_snapshot = uuid_label.clone();
                        async move {
                            let mut client = agent.get_i_client();
                            let resp = client.get_info(AgentGetInfoRequest {}).await?;
                            let info = resp.into_inner();
                            Ok(AgentSnapshot {
                                uuid: uuid_for_snapshot,
                                cpu:  f64::from(info.cpu),
                                mem:  f64::from(info.mem),
                                disk: f64::from(info.disk),
                            })
                        }
                    })
                    .await
                    .map_err(|e| e.to_string());
                drop(permit);
                snapshot
            });
        }

        let mut snapshots = Vec::new();
        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok(Ok(snapshot)) => snapshots.push(snapshot),
                Ok(Err(err)) => warn!("Failed to pull agent info: {err}"),
                Err(join_err) => error!("Join error while collecting agent info: {join_err}"),
            }
        }

        if snapshots.is_empty() {
            return Err("Failed to retrieve metrics from agents".into());
        }

        Ok(snapshots)
    }

    async fn collect_server_hosts(
        &self,
        server: &str,
        command: AgentCommand,
    ) -> Result<HashMap<String, CommonInfo>, Status> {
        let descriptors = Self::agent_descriptors(None);
        if descriptors.is_empty() {
            return Ok(HashMap::new());
        }

        let concurrency = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let permits = if concurrency == 0 { 1 } else { concurrency };
        let semaphore = Arc::new(Semaphore::new(permits));
        let mut set = JoinSet::new();

        for descriptor in descriptors {
            let clients = self.grpc_clients.clone();
            let semaphore = Arc::clone(&semaphore);
            let server_name = server.to_string();
            let uuid = descriptor.uuid.to_string();
            set.spawn(async move {
                let permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return Err((uuid.clone(), "semaphore closed".to_string())),
                };
                let argument_json = json!({ "Server": server_name }).to_string();
                let response = clients
                    .with_agent_uuid_handle(&uuid, move |agent| {
                        let argument = Some(argument_json.clone());
                        async move {
                            let mut client = agent.get_m_client();
                            let resp = client
                                .execute_command(CommandRequest {
                                    command: command as i32,
                                    argument,
                                })
                                .await?;
                            Ok(resp.into_inner())
                        }
                    })
                    .await;
                drop(permit);

                match response {
                    Ok(payload) => match payload.payload {
                        Some(command_response::Payload::ServerHostInfo(info)) => {
                            Ok(Some((uuid, convert_server_host_info(info))))
                        }
                        Some(command_response::Payload::ReturnInfo(info)) => {
                            debug!(
                                %uuid,
                                server = server_name,
                                status = info.r#type,
                                message = info.message,
                                "server host skipped"
                            );
                            Ok(None)
                        }
                        other => {
                            warn!(%uuid, "unexpected payload for server query: {:?}", other);
                            Ok(None)
                        }
                    },
                    Err(err) => Err((uuid, err.to_string())),
                }
            });
        }

        let mut pcs = HashMap::new();
        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok(Ok(Some((uuid, info)))) => {
                    pcs.insert(uuid, info);
                }
                Ok(Ok(None)) => {}
                Ok(Err((uuid, message))) => {
                    warn!(%uuid, "server host query failed: {message}");
                }
                Err(join_err) => error!("Join error while collecting server hosts: {join_err}"),
            }
        }

        Ok(pcs)
    }

    async fn execute_agent_command(
        &self,
        uuid: &str,
        command: AgentCommand,
        argument: Option<String>,
    ) -> Result<agent::CommandResponse, Status> {
        let uuid_owned = uuid.to_string();
        let argument_owned = argument.clone();
        self.grpc_clients
            .with_agent_uuid_handle(&uuid_owned, move |agent| {
                let argument = argument_owned.clone();
                async move {
                    let mut client = agent.get_m_client();
                    let resp = client
                        .execute_command(CommandRequest { command: command as i32, argument })
                        .await?;
                    Ok(resp.into_inner())
                }
            })
            .await
            .map_err(|e| Status::internal(e.to_string()))
    }
}

fn classify_metric(value: f64, threshold: &MetricThreshold) -> NodeStatus {
    if value >= threshold.danger {
        NodeStatus::Danger
    } else if value >= threshold.warn {
        NodeStatus::Warn
    } else {
        NodeStatus::Safe
    }
}

fn classify_snapshot(snapshot: &AgentSnapshot, threshold: &InfoThresholds) -> NodeStatus {
    let cpu = classify_metric(snapshot.cpu, &threshold.cpu);
    let memory = classify_metric(snapshot.mem, &threshold.memory);
    let disk = classify_metric(snapshot.disk, &threshold.disk);
    *[cpu, memory, disk].iter().max().unwrap_or(&NodeStatus::Safe)
}

fn node_status_to_info_status(status: NodeStatus) -> restful::InfoStatus {
    match status {
        NodeStatus::Safe => restful::InfoStatus::Safe,
        NodeStatus::Warn => restful::InfoStatus::Warn,
        NodeStatus::Danger => restful::InfoStatus::Dang,
    }
}

fn threshold_to_metric_setting(threshold: &MetricThreshold) -> restful::MetricSetting {
    restful::MetricSetting { warn: threshold.warn, dang: threshold.danger }
}

fn validate_metric_setting(setting: &restful::MetricSetting) -> Result<(), &'static str> {
    if !setting.warn.is_finite() || !setting.dang.is_finite() {
        return Err("warn and dang must be finite numbers");
    }
    if setting.warn < 0.0 || setting.dang < 0.0 {
        return Err("warn and dang must be non-negative");
    }
    if setting.warn >= setting.dang {
        return Err("dang must be greater than warn");
    }
    Ok(())
}

fn metric_setting_to_threshold(
    setting: &restful::MetricSetting,
) -> Result<MetricThreshold, &'static str> {
    validate_metric_setting(setting)?;
    Ok(MetricThreshold { warn: setting.warn, danger: setting.dang })
}

// TODO: 由RestFul Server 為Client 調用Controller RestFul gRPC介面
#[derive(Debug)]
pub struct ControllerRestfulServer {
    pub grpc_clients: Arc<GrpcClients>,
    pub config:       (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
}

#[allow(clippy::result_large_err)]
fn parse_agent_uuid_input(raw: &str) -> Result<(Uuid, String), Status> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument("必須提供目標主機的 UUID"));
    }
    let parsed =
        Uuid::parse_str(trimmed).map_err(|_| Status::invalid_argument("UUID 格式不正確"))?;
    Ok((parsed, trimmed.to_string()))
}

#[allow(clippy::result_large_err)]
fn parse_apache_action_uuid(uuid: &str, action: &str) -> Result<(Uuid, String), Status> {
    if uuid.trim().is_empty() {
        return Err(Status::invalid_argument(format!("{action} 需要提供 UUID")));
    }
    parse_agent_uuid_input(uuid)
}

#[allow(clippy::result_large_err)]
fn parse_server_name_input(raw: &str) -> Result<String, Status> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument("Server 名稱不可為空"));
    }
    Ok(trimmed.to_string())
}

#[allow(clippy::result_large_err)]
fn extract_apache_info(resp: agent::CommandResponse) -> Result<agent::ApacheInfo, Status> {
    match resp.payload {
        Some(command_response::Payload::ApacheInfo(info)) => Ok(info),
        Some(command_response::Payload::ReturnInfo(info)) => Err(Status::internal(info.message)),
        _ => Err(Status::internal("Agent 傳回未知資料格式")),
    }
}

#[allow(clippy::result_large_err)]
fn extract_return_info(resp: agent::CommandResponse) -> Result<agent::ReturnInfo, Status> {
    match resp.payload {
        Some(command_response::Payload::ReturnInfo(info)) => Ok(info),
        _ => Err(Status::internal("Agent 傳回未知資料格式")),
    }
}

fn convert_return_info_to_action_result(info: agent::ReturnInfo) -> ActionResult {
    let action_type = match info.r#type.to_ascii_uppercase().as_str() {
        "OK" => action_result::Type::Ok as i32,
        "ERR" => action_result::Type::Err as i32,
        _ => action_result::Type::Unspecified as i32,
    };
    ActionResult { r#type: action_type, message: info.message }
}

fn convert_server_host_info(info: agent::ServerHostInfo) -> CommonInfo {
    let status_enum = agent::server_host_info::Status::try_from(info.status)
        .unwrap_or(agent::server_host_info::Status::ServerStatusUnspecified);
    let status = match status_enum {
        agent::server_host_info::Status::Active => CommonStatus::Active as i32,
        agent::server_host_info::Status::Stopped => CommonStatus::Stopped as i32,
        agent::server_host_info::Status::Uninstalled => CommonStatus::Uninstalled as i32,
        _ => CommonStatus::Unspecified as i32,
    };

    CommonInfo { hostname: info.hostname, status, cpu: info.cpu, memory: info.memory, ip: info.ip }
}

fn resolve_server_package(server: &str, info: &agent::SystemInfo) -> Result<&'static str, String> {
    match server.to_ascii_lowercase().as_str() {
        "apache" => {
            let os = info.os_id.to_ascii_lowercase();
            if is_redhat_family(&os) {
                Ok("httpd")
            } else if is_debian_family(&os) {
                Ok("apache2")
            } else {
                Err(format!("不支援在 {os} 上安裝 Apache"))
            }
        }
        _ => Err(format!("{server} 尚未支援安裝")),
    }
}

fn is_redhat_family(os: &str) -> bool {
    matches!(
        os,
        "centos" | "rocky" | "rhel" | "almalinux" | "scientific" | "oracle" | "fedora" | "redhat"
    )
}

fn is_debian_family(os: &str) -> bool {
    matches!(os, "debian" | "ubuntu" | "kali" | "linuxmint" | "raspbian" | "elementary" | "pop")
}

#[allow(clippy::result_large_err)]
fn convert_agent_apache_info(info: agent::ApacheInfo) -> Result<GetApacheResponse, Status> {
    let apache_status =
        agent::ApacheStatus::try_from(info.status).unwrap_or(agent::ApacheStatus::Unspecified);
    let status = match apache_status {
        agent::ApacheStatus::Active => CommonStatus::Active as i32,
        agent::ApacheStatus::Stopped => CommonStatus::Stopped as i32,
        agent::ApacheStatus::Uninstalled => CommonStatus::Uninstalled as i32,
        _ => CommonStatus::Unspecified as i32,
    };

    let logs = info.logs.map(convert_agent_logs);
    let common_info = Some(CommonInfo {
        hostname: info.hostname,
        status,
        cpu: info.cpu,
        memory: info.memory,
        ip: info.ip,
    });

    Ok(GetApacheResponse { common_info, connections: info.connections, logs })
}

fn convert_agent_logs(logs: agent::ApacheLogs) -> restful::ApacheLogs {
    let error_log = logs.error_log.into_iter().map(convert_error_log).collect();
    let access_log = logs.access_log.into_iter().map(convert_access_log).collect();
    restful::ApacheLogs {
        error_log,
        errlength: logs.errlength,
        access_log,
        acclength: logs.acclength,
    }
}

fn convert_error_log(entry: agent::ApacheErrorLog) -> ErrorLog {
    let log_level =
        agent::ApacheLogLevel::try_from(entry.level).unwrap_or(agent::ApacheLogLevel::Unspecified);
    let level = match log_level {
        agent::ApacheLogLevel::Debug => LogLevel::Debug as i32,
        agent::ApacheLogLevel::Info => LogLevel::Info as i32,
        agent::ApacheLogLevel::Notice => LogLevel::Notice as i32,
        agent::ApacheLogLevel::Warn => LogLevel::Warn as i32,
        agent::ApacheLogLevel::Error => LogLevel::Error as i32,
        agent::ApacheLogLevel::Crit => LogLevel::Crit as i32,
        agent::ApacheLogLevel::Alert => LogLevel::Alert as i32,
        agent::ApacheLogLevel::Emerg => LogLevel::Emerg as i32,
        _ => LogLevel::Unspecified as i32,
    };

    ErrorLog {
        date: entry.date.and_then(convert_apache_date),
        module: entry.module,
        level,
        pid: entry.pid,
        client: entry.client,
        message: entry.message,
    }
}

fn convert_access_log(entry: agent::ApacheAccessLog) -> restful::ApacheAccessLog {
    restful::ApacheAccessLog {
        ip:         entry.ip,
        date:       entry.date.and_then(convert_apache_date),
        method:     entry.method,
        url:        entry.url,
        protocol:   entry.protocol,
        status:     entry.status,
        byte:       entry.byte,
        referer:    entry.referer,
        user_agent: entry.user_agent,
    }
}

fn convert_apache_date(date: agent::ApacheDate) -> Option<Date> {
    let year = u64::try_from(date.year).ok()?;
    let month_enum =
        agent::ApacheMonth::try_from(date.month).unwrap_or(agent::ApacheMonth::Unspecified);
    let month = match month_enum {
        agent::ApacheMonth::Jan => Month::Jan as i32,
        agent::ApacheMonth::Feb => Month::Feb as i32,
        agent::ApacheMonth::Mar => Month::Mar as i32,
        agent::ApacheMonth::Apr => Month::Apr as i32,
        agent::ApacheMonth::May => Month::May as i32,
        agent::ApacheMonth::Jun => Month::Jun as i32,
        agent::ApacheMonth::Jul => Month::Jul as i32,
        agent::ApacheMonth::Aug => Month::Aug as i32,
        agent::ApacheMonth::Sep => Month::Sep as i32,
        agent::ApacheMonth::Oct => Month::Oct as i32,
        agent::ApacheMonth::Nov => Month::Nov as i32,
        agent::ApacheMonth::Dec => Month::Dec as i32,
        _ => Month::Unspecified as i32,
    };

    let week_enum =
        agent::ApacheWeek::try_from(date.week).unwrap_or(agent::ApacheWeek::Unspecified);
    let week = match week_enum {
        agent::ApacheWeek::Mon => Week::Mon as i32,
        agent::ApacheWeek::Tue => Week::Tue as i32,
        agent::ApacheWeek::Wed => Week::Wed as i32,
        agent::ApacheWeek::Thu => Week::Thu as i32,
        agent::ApacheWeek::Fri => Week::Fri as i32,
        agent::ApacheWeek::Sat => Week::Sat as i32,
        agent::ApacheWeek::Sun => Week::Sun as i32,
        _ => Week::Unspecified as i32,
    };

    let time =
        date.time.map(|t| common::date::Time { hour: u64::from(t.hour), min: u64::from(t.min) });
    let day = u64::try_from(date.day).ok().unwrap_or(0);

    Some(Date { year, month, week, time, day })
}

#[tonic::async_trait]
impl RestfulService for ControllerRestfulServer {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        let req_username_clone = req.username.clone();
        let resp = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                ldap.authenticate_user(req_username_clone, req.password).await
            })
            .await;
        let res = resp
            .map_err(|e| Status::internal(e.to_string()))
            .inspect_err(|e| tracing::error!(?e))?;
        if !res {
            Err(Status::permission_denied(format!("Invalid credentials for user {}", req.username)))
        } else {
            let resp = LoginResponse {
                result: Some(ResponseResult {
                    r#type:  ResponseType::Ok as i32,
                    message: "Login successful".to_string(),
                }),
            };
            Ok(Response::new(resp))
        }
    }

    async fn get_all_info(
        &self,
        request: Request<GetAllInfoRequest>,
    ) -> Result<Response<GetAllInfoResponse>, Status> {
        let _ = request;
        let snapshots = self
            .collect_agent_snapshots(None)
            .await
            .map_err(|e| Status::internal(format!("Failed to collect agent info: {e}")))?;
        let thresholds = GlobalConfig::with(|cfg| cfg.extend.info_thresholds.clone());

        let mut total_cpu = 0.0;
        let mut total_mem = 0.0;
        let mut total_disk = 0.0;
        let mut counts = InfoCounts { safe: 0, warn: 0, dang: 0 };
        for snapshot in &snapshots {
            total_cpu += snapshot.cpu;
            total_mem += snapshot.mem;
            total_disk += snapshot.disk;
            match classify_snapshot(snapshot, &thresholds) {
                NodeStatus::Safe => counts.safe += 1,
                NodeStatus::Warn => counts.warn += 1,
                NodeStatus::Danger => counts.dang += 1,
            }
        }

        let count = snapshots.len() as f64;
        let cluster = ClusterSummary {
            cpu:    if count > 0.0 { ((total_cpu / count) * 100.0).round() / 100.0 } else { 0.0 },
            memory: if count > 0.0 { ((total_mem / count) * 100.0).round() / 100.0 } else { 0.0 },
            disk:   if count > 0.0 { ((total_disk / count) * 100.0).round() / 100.0 } else { 0.0 },
        };
        let info_counts = InfoCounts { safe: counts.safe, warn: counts.warn, dang: counts.dang };

        Ok(Response::new(GetAllInfoResponse { info: Some(info_counts), cluster: Some(cluster) }))
    }

    async fn get_info(
        &self,
        request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let req = request.into_inner();
        let requested_uuid_raw = req.uuid.and_then(|u| {
            let trimmed = u.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let target_uuid = if let Some(ref uuid_str) = requested_uuid_raw {
            let parsed = Uuid::parse_str(uuid_str)
                .map_err(|_| Status::invalid_argument(format!("Invalid uuid: {uuid_str}")))?;
            if !Self::agent_exists(&parsed) {
                return Err(Status::not_found(format!("Agent {uuid_str} not found")));
            }
            Some(parsed)
        } else {
            None
        };
        let requested_target =
            restful::Target::try_from(req.target).unwrap_or(restful::Target::Unspecified);
        let status_filter = match requested_target {
            restful::Target::Safe => Some(NodeStatus::Safe),
            restful::Target::Warn => Some(NodeStatus::Warn),
            restful::Target::Dang => Some(NodeStatus::Danger),
            _ => None,
        };

        let snapshots = self
            .collect_agent_snapshots(target_uuid)
            .await
            .map_err(|e| Status::internal(format!("Failed to collect agent info: {e}")))?;
        let thresholds = GlobalConfig::with(|cfg| cfg.extend.info_thresholds.clone());

        let mut pcs = HashMap::new();
        for snapshot in snapshots {
            let cpu_status = classify_metric(snapshot.cpu, &thresholds.cpu);
            let memory_status = classify_metric(snapshot.mem, &thresholds.memory);
            let disk_status = classify_metric(snapshot.disk, &thresholds.disk);
            let status =
                *[cpu_status, memory_status, disk_status].iter().max().unwrap_or(&NodeStatus::Safe);
            if let Some(expected) = status_filter {
                if status != expected {
                    continue;
                }
            }
            pcs.insert(
                snapshot.uuid.clone(),
                PcMetrics {
                    cpu:           (snapshot.cpu * 100.0).round() / 100.0,
                    memory:        (snapshot.mem * 100.0).round() / 100.0,
                    disk:          (snapshot.disk * 100.0).round() / 100.0,
                    cpu_status:    node_status_to_info_status(cpu_status) as i32,
                    memory_status: node_status_to_info_status(memory_status) as i32,
                    disk_status:   node_status_to_info_status(disk_status) as i32,
                },
            );
        }
        let length = pcs.len() as u64;

        Ok(Response::new(GetInfoResponse { pcs, length }))
    }

    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        todo!()
    }

    async fn backup_now(
        &self,
        request: Request<BackupNowRequest>,
    ) -> Result<Response<BackupNowResponse>, Status> {
        todo!()
    }

    async fn get_backups(
        &self,
        request: Request<GetBackupsRequest>,
    ) -> Result<Response<GetBackupsResponse>, Status> {
        todo!()
    }

    async fn reduce_backup(
        &self,
        request: Request<ReductionRequest>,
    ) -> Result<Response<ReductionResponse>, Status> {
        todo!()
    }

    async fn get_valid_certs(
        &self,
        request: Request<GetValidCertsRequest>,
    ) -> Result<Response<GetValidCertsResponse>, Status> {
        let r = self
            .grpc_clients
            .with_ca_handle(|ca| async move { ca.get_all_certificates().await })
            .await
            .map_err(|e| Status::internal(format!("Failed to get valid certificates: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let vaild_certs: Vec<ValidCert> = r
            .iter()
            .map(|cert| ValidCert {
                name:   cert.subject_cn.clone(),
                signer: cert.issuer.clone(),
                period: cert.expiration.as_ref().map(CertUtils::ts_to_string).unwrap_or_default(),
            })
            .collect();
        let length = vaild_certs.len() as u64;
        let ret = GetValidCertsResponse { valid: vaild_certs, length };
        Ok(Response::new(ret))
    }

    async fn get_revoked_certs(
        &self,
        request: Request<GetRevokedCertsRequest>,
    ) -> Result<Response<GetRevokedCertsResponse>, Status> {
        let r = self
            .grpc_clients
            .with_ca_handle(|ca| async move { ca.get_all_revoked_certificates().await })
            .await
            .map_err(|e| Status::internal(format!("Failed to get revoked certificates: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let revoked_certs: Vec<RevokedCert> = r
            .iter()
            .map(|entry| RevokedCert {
                number: entry.cert_serial.clone(),
                time:   entry.revoked_at.as_ref().map(CertUtils::ts_to_string).unwrap_or_default(),
                reason: entry.reason.clone(),
            })
            .collect();
        let length = revoked_certs.len() as u64;
        let ret = GetRevokedCertsResponse { revoke: revoked_certs, length };
        Ok(Response::new(ret))
    }

    async fn revoke_cert(
        &self,
        request: Request<RevokeCertRequest>,
    ) -> Result<Response<RevokeCertResponse>, Status> {
        let RevokeCertRequest { name, reason } = request.into_inner();
        let name_cloned = name.clone();
        let cert = self
            .grpc_clients
            .with_ca_handle(|ca| async move {
                ca.get_certificate_by_common_name(name_cloned.clone()).await
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to get serail {name}: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let cert = match cert {
            Some(c) => c,
            None => return Err(Status::not_found(format!("Certificate {name} not found"))),
        };
        self.grpc_clients
            .with_ca_handle(|ca| async move {
                ca.mark_certificate_as_revoked(cert.serial, Some(reason)).await
            })
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke certificate {name}: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        // TODO: 等到後面Agent成功合併之後，需要修改
        let (pri_key, same_name_csr) = CertUtils::generate_csr_with_new_key(
            4096,
            "TW",
            "Taipei",
            "Taipei",
            "CHM.com",
            &name,
            ["127.0.0.1", &name],
        )
        .map_err(|e| Status::internal(e.to_string()))
        .inspect_err(|e| tracing::error!(?e))?;
        let sign_days = GlobalConfig::with(|cfg| cfg.extend.sign_days);
        self.grpc_clients
            .with_ca_handle(|ca| async move { ca.sign_certificate(same_name_csr, sign_days).await })
            .await
            .map_err(|e| Status::internal(format!("Failed to sign certificate: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("憑證 {name} 已成功註銷"),
        };
        let resp = RevokeCertResponse { result: Some(result) };
        Ok(Response::new(resp))
    }

    async fn add_pc(
        &self,
        request: Request<AddPcRequest>,
    ) -> Result<Response<AddPcResponse>, Status> {
        use crate::Node;
        let req = request.into_inner();
        // TODO: 預設PC Group 要先在啟動時創建，添加Agent時直接加入預設Group(vni=1)
        let ip: SocketAddr = req
            .ip
            .parse()
            .map_err(|e| {
                Status::invalid_argument(format!("Invalid IP address format for '{}': {e}", req.ip))
            })
            .inspect_err(|e| tracing::error!(?e))?;
        let node_h = Node::new(
            Some(req.ip),
            Some(req.password),
            self.grpc_clients.clone(),
            self.config.clone(),
        );
        node_h
            .add(false)
            .await
            .map_err(|e| Status::internal(e.to_string()))
            .inspect_err(|e| tracing::error!(?e))?;
        let resp = AddPcResponse {
            result: Some(ResponseResult {
                r#type:  ResponseType::Ok as i32,
                message: "添加主機成功".to_string(),
            }),
        };
        Ok(Response::new(resp))
    }

    async fn get_all_pcs(
        &self,
        _request: Request<GetAllPcsRequest>,
    ) -> Result<Response<GetAllPcsResponse>, Status> {
        let services: Vec<ServiceDescriptor> = GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .iter()
                .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
                .collect()
        });
        // TODO: 可能需要檢查API Server 的存活狀態

        let mut pcs: HashMap<String, PcSimple> = HashMap::new();
        for service in services.iter() {
            let mut status = false;

            if let Some(health_name) = service.health_name.as_deref() {
                let channels = self.grpc_clients.all_channels(service.kind);
                if channels.is_empty() {
                    tracing::warn!(
                        "找不到 {:?} 的任何 channel，略過健康檢查（{}）",
                        service.kind,
                        service.hostname
                    );
                } else {
                    for ch in channels {
                        let mut hc = HealthClient::new(ch);
                        match hc
                            .check(HealthCheckRequest { service: health_name.to_string() })
                            .await
                        {
                            Ok(resp) => {
                                let s = resp.into_inner().status;
                                if s == ServingStatus::Serving as i32 {
                                    status = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("健康檢查失敗: {} ({})", service.hostname, e);
                            }
                        }
                    }
                }
            } else {
                tracing::info!("{} 未設定 health_name，跳過健康檢查", service.hostname);
            }
            let pc =
                PcSimple { ip: service.uri.clone(), hostname: service.hostname.clone(), status };
            pcs.insert(service.uuid.to_string(), pc);
        }

        let length = pcs.len() as u64;
        Ok(Response::new(GetAllPcsResponse { pcs, length }))
    }
    // TODO: 這裡的status只是先去看healthService的狀態，
    // 後面需要透過heatbeat機制來更新
    async fn get_specific_pcs(
        &self,
        request: Request<GetSpecificPcsRequest>,
    ) -> Result<Response<GetSpecificPcsResponse>, Status> {
        let data = request.into_inner();
        let wanted: HashSet<Uuid> = data
            .uuid
            .into_iter()
            .filter_map(|s| match Uuid::parse_str(&s) {
                Ok(u) => Some(u),
                Err(e) => {
                    tracing::warn!("忽略無效的 UUID '{s}': {e}");
                    None
                }
            })
            .collect();
        let services: HashSet<ServiceDescriptor> = GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .iter()
                .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
                .collect()
        });
        let filtered = services.into_iter().filter(|s| wanted.contains(&s.uuid));
        let mut pcs: HashMap<String, PcSimple> = HashMap::new();
        for service in filtered {
            let mut status = false;
            if let Some(health_name) = service.health_name.as_deref() {
                let channels = self.grpc_clients.all_channels(service.kind);
                if channels.is_empty() {
                    tracing::warn!(
                        "找不到 {:?} 的任何 channel，略過健康檢查（{}）",
                        service.kind,
                        service.hostname
                    );
                } else {
                    for ch in channels {
                        let mut hc = HealthClient::new(ch);
                        match hc
                            .check(HealthCheckRequest { service: health_name.to_string() })
                            .await
                        {
                            Ok(resp) => {
                                let s = resp.into_inner().status;
                                if s == ServingStatus::Serving as i32 {
                                    status = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("健康檢查失敗: {} ({})", service.hostname, e);
                            }
                        }
                    }
                }
            } else {
                tracing::info!("{} 未設定 health_name，跳過健康檢查", service.hostname);
            }
            let pc =
                PcSimple { ip: service.uri.clone(), hostname: service.hostname.clone(), status };
            pcs.insert(service.uuid.to_string(), pc);
        }
        let length = pcs.len() as u64;
        Ok(Response::new(GetSpecificPcsResponse { pcs, length }))
    }

    async fn delete_pcs(
        &self,
        request: Request<DeletePcsRequest>,
    ) -> Result<Response<DeletePcsResponse>, Status> {
        // RestFul API
        // 只能移除Agent，不能移除基礎服務,
        // 必須透過Controller的Cli或後續grpc介面來移除基礎服務
        // TODO: controller lib.rs: Node struct 需要與Agent通訊之後才能移除
        use crate::Node;
        let req = request.into_inner();
        let mut results = HashMap::new();
        for pc in req.uuids {
            let d_pc = GlobalConfig::with(|cfg| {
                cfg.extend.services_pool.services.iter().find_map(|entry| {
                    entry.value().iter().find(|s| s.uuid.to_string() == pc).cloned()
                })
            });
            if d_pc.is_none() {
                results.insert(
                    pc,
                    ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: "找不到主機資訊".to_string(),
                    },
                );
                continue;
            }
            let d_pc = d_pc.unwrap();
            let d_pc_uuid = d_pc.uuid.to_string();
            let node_h =
                Node::new(Some(d_pc_uuid), None, self.grpc_clients.clone(), self.config.clone());
            if let Err(e) = node_h.remove("agent", false).await {
                results.insert(
                    pc,
                    ResponseResult { r#type: ResponseType::Err as i32, message: format!("{e}") },
                );
                continue;
            }
            results.insert(
                pc,
                ResponseResult {
                    r#type:  ResponseType::Ok as i32,
                    message: "刪除主機成功".to_string(),
                },
            );
        }
        let resp = DeletePcsResponse { results };
        Ok(Response::new(resp))
    }

    async fn reboot_pcs(
        &self,
        request: Request<RebootPcsRequest>,
    ) -> Result<Response<RebootPcsResponse>, Status> {
        let req = request.into_inner();
        let uuids = req.uuids;
        let total = uuids.len() as u32;
        let max_concurrent = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut set: JoinSet<(String, ResponseResult)> = JoinSet::new();
        let mut results = HashMap::new();
        for uuid in uuids {
            let exists = GlobalConfig::with(|cfg| {
                cfg.extend
                    .services_pool
                    .services
                    .iter()
                    .any(|entry| entry.value().iter().any(|s| s.uuid.to_string() == uuid))
            });
            if !exists {
                results.insert(
                    uuid.clone(),
                    ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: "找不到主機資訊".into(),
                    },
                );
                continue;
            }
            let sem = semaphore.clone();
            let clients = self.grpc_clients.clone();
            set.spawn(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            uuid,
                            ResponseResult {
                                r#type:  ResponseType::Err as i32,
                                message: "Semaphore closed".to_string(),
                            },
                        );
                    }
                };
                let ret = clients
                    .with_agent_uuid_handle(
                        &uuid,
                        |agent| async move { agent.reboot_system().await },
                    )
                    .await;
                match ret {
                    Ok(true) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Ok as i32,
                            message: "Reboot succeeded".to_string(),
                        },
                    ),
                    Ok(false) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: "Agent reported failure".to_string(),
                        },
                    ),
                    Err(e) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: format!("RPC error: {e}"),
                        },
                    ),
                }
            });
        }
        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok((uuid, result)) => {
                    results.insert(uuid, result);
                }
                Err(join_err) => {
                    results.insert(
                        format!("unknown-{}", results.len() + 1),
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: format!("Join error: {join_err}"),
                        },
                    );
                }
            }
        }
        Ok(Response::new(RebootPcsResponse { results }))
    }

    async fn shutdown_pcs(
        &self,
        request: Request<ShutdownPcsRequest>,
    ) -> Result<Response<ShutdownPcsResponse>, Status> {
        let req = request.into_inner();
        let uuids = req.uuids;
        let total = uuids.len() as u32;
        let max_concurrent = GlobalConfig::with(|cfg| cfg.extend.concurrency);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut set: JoinSet<(String, ResponseResult)> = JoinSet::new();
        let mut results = HashMap::new();
        for uuid in uuids {
            let exists = GlobalConfig::with(|cfg| {
                cfg.extend
                    .services_pool
                    .services
                    .iter()
                    .any(|entry| entry.value().iter().any(|s| s.uuid.to_string() == uuid))
            });
            if !exists {
                results.insert(
                    uuid.clone(),
                    ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: "找不到主機資訊".into(),
                    },
                );
                continue;
            }
            let sem = semaphore.clone();
            let clients = self.grpc_clients.clone();
            set.spawn(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        return (
                            uuid,
                            ResponseResult {
                                r#type:  ResponseType::Err as i32,
                                message: "Semaphore closed".to_string(),
                            },
                        );
                    }
                };
                let ret = clients
                    .with_agent_uuid_handle(
                        &uuid,
                        |agent| async move { agent.shutdown_system().await },
                    )
                    .await;
                match ret {
                    Ok(true) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Ok as i32,
                            message: "Shutdown succeeded".to_string(),
                        },
                    ),
                    Ok(false) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: "Agent reported failure".to_string(),
                        },
                    ),
                    Err(e) => (
                        uuid,
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: format!("RPC error: {e}"),
                        },
                    ),
                }
            });
        }
        while let Some(join_res) = set.join_next().await {
            match join_res {
                Ok((uuid, result)) => {
                    results.insert(uuid, result);
                }
                Err(join_err) => {
                    results.insert(
                        format!("unknown-{}", results.len() + 1),
                        ResponseResult {
                            r#type:  ResponseType::Err as i32,
                            message: format!("Join error: {join_err}"),
                        },
                    );
                }
            }
        }
        Ok(Response::new(ShutdownPcsResponse { results }))
    }

    async fn get_pc_groups(
        &self,
        request: Request<GetPcGroupsRequest>,
    ) -> Result<Response<GetPcGroupsResponse>, Status> {
        let (groups, length) = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let zones = dhcp
                    .list_zones()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list DHCP zones: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                let mut groups: HashMap<i64, PcGroup> = HashMap::new();
                for zone in zones {
                    let id = zone.vni;
                    let zone_name = zone.name;
                    let pcs = dhcp
                        .list_pcs_in_zone(&zone_name)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))
                        .inspect_err(|e| tracing::error!(?e))?;
                    let group = PcGroup { groupname: zone_name, pcs };
                    groups.insert(id, group);
                }
                let length = groups.len() as u64;
                Ok((groups, length))
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let resp = GetPcGroupsResponse { groups, length };
        Ok(Response::new(resp))
    }

    async fn create_pc_group(
        &self,
        request: Request<CreatePcGroupRequest>,
    ) -> Result<Response<CreatePcGroupResponse>, Status> {
        let req = request.into_inner();
        let result = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let vni = dhcp
                    .list_zones()
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .last()
                    .map(|zone| zone.vni + 1)
                    .unwrap_or(10);
                let status = dhcp
                    .create_zone(req.groupname, vni, req.cidr)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))
                    .inspect_err(|e| tracing::error!(?e))?;
                if !status {
                    Ok(ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: "Failed to create PC group".to_string(),
                    })
                } else {
                    Ok(ResponseResult {
                        r#type:  ResponseType::Ok as i32,
                        message: "PC group created successfully".to_string(),
                    })
                }
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = Some(result);
        let resp = CreatePcGroupResponse { result };
        Ok(Response::new(resp))
    }

    async fn put_pc_group(
        &self,
        request: Request<PutPcGroupRequest>,
    ) -> Result<Response<PutPcGroupResponse>, Status> {
        let req = request.into_inner();
        let final_pcs_resp = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let vxlanid = req.vxlanid;
                let group = req
                    .group
                    .ok_or_else(|| Status::invalid_argument("PcGroup is required"))
                    .inspect_err(|e| tracing::error!(?e))?;
                let detail = dhcp
                    .get_zone_detail_by_vni(vxlanid)
                    .await
                    .map_err(|e| Status::internal(format!("get_zone_detail_by_vni failed: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                if !group.groupname.is_empty() && group.groupname != detail.name {
                    dhcp.update_zone_name_by_vni(vxlanid, group.groupname.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!("update_zone_name_by_vni failed: {e}"))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                }
                let desired_uuid_set: HashSet<String> = group
                    .pcs
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let current_pcs_resp = dhcp
                    .list_pcs_in_zone_by_vni(vxlanid)
                    .await
                    .map_err(|e| Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                let current_uuid_set: HashSet<String> = current_pcs_resp.into_iter().collect();
                let to_add: Vec<String> =
                    desired_uuid_set.difference(&current_uuid_set).cloned().collect();
                let to_remove: Vec<String> =
                    current_uuid_set.difference(&desired_uuid_set).cloned().collect();
                let add_futs = to_add.iter().map(|uuid| {
                    let c = dhcp.clone();
                    let uuid = uuid.clone();
                    async move { c.add_pc_to_zone_by_vni(vxlanid, uuid).await }
                });
                let remove_futs = to_remove.iter().map(|uuid| {
                    let c = dhcp.clone();
                    let uuid = uuid.clone();
                    async move { c.remove_pc_from_zone_by_vni(vxlanid, uuid).await }
                });
                let _add_results = join_all(add_futs).await;
                let _remove_results = join_all(remove_futs).await;
                let final_pcs_resp = dhcp
                    .list_pcs_in_zone_by_vni(vxlanid)
                    .await
                    .map_err(|e| Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                Ok(final_pcs_resp)
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let resp = PutPcGroupResponse {
            result: Some(ResponseResult {
                r#type:  ResponseType::Ok as i32,
                message: format!(
                    "PC group updated successfully, total PCs: {}",
                    final_pcs_resp.len()
                ),
            }),
        };
        Ok(Response::new(resp))
    }

    async fn patch_pc_group(
        &self,
        request: Request<PatchPcGroupRequest>,
    ) -> Result<Response<PatchPcGroupResponse>, Status> {
        let req = request.into_inner();
        let vni = req.vxlanid;
        let result = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let ret = match req.kind {
                    Some(patch_pc_group_request::Kind::Groupname(new_name)) => {
                        match dhcp.update_zone_name_by_vni(vni, new_name).await {
                            Ok(resp) => {
                                if resp {
                                    ResponseResult {
                                        r#type:  ResponseType::Ok as i32,
                                        message: "Zone name updated successfully".to_string(),
                                    }
                                } else {
                                    ResponseResult {
                                        r#type:  ResponseType::Err as i32,
                                        message: "Failed to update zone name".to_string(),
                                    }
                                }
                            }
                            Err(e) => ResponseResult {
                                r#type:  ResponseType::Err as i32,
                                message: format!("update_zone_name_by_vni failed: {e}"),
                            },
                        }
                    }
                    Some(patch_pc_group_request::Kind::Pcs(pcs_msg)) => {
                        let current = dhcp
                            .list_pcs_in_zone_by_vni(vni)
                            .await
                            .map_err(|e| {
                                Status::internal(format!("list_pcs_in_zone_by_vni failed: {e}"))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                        let current_set: HashSet<String> = current.into_iter().collect();
                        let desired_set: HashSet<String> = pcs_msg
                            .pcs
                            .into_iter()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let to_add: Vec<String> =
                            desired_set.difference(&current_set).cloned().collect();
                        let to_remove: Vec<String> =
                            current_set.difference(&desired_set).cloned().collect();
                        let mut set = JoinSet::new();
                        for uuid in &to_add {
                            let c = dhcp.clone();
                            let uuid = uuid.clone();
                            set.spawn(async move {
                                let res = c.add_pc_to_zone_by_vni(vni, uuid.clone()).await;
                                ("add", uuid, res)
                            });
                        }
                        for uuid in &to_remove {
                            let c = dhcp.clone();
                            let uuid = uuid.clone();
                            set.spawn(async move {
                                let res = c.remove_pc_from_zone_by_vni(vni, uuid.clone()).await;
                                ("remove", uuid, res)
                            });
                        }
                        while set.join_next().await.is_some() {}
                        ResponseResult {
                            r#type:  ResponseType::Ok as i32,
                            message: "PCs updated successfully".into(),
                        }
                    }
                    None => ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: "Missing patch kind".into(),
                    },
                };
                Ok(ret)
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        Ok(Response::new(PatchPcGroupResponse { result: Some(result) }))
    }

    async fn delete_pc_group(
        &self,
        request: Request<DeletePcGroupRequest>,
    ) -> Result<Response<DeletePcGroupResponse>, Status> {
        let req = request.into_inner();
        let result = self
            .grpc_clients
            .with_dhcp_handle(|dhcp| async move {
                let vni = req.vxlanid;
                let zone = dhcp
                    .get_zone_detail_by_vni(vni)
                    .await
                    .map_err(|e| Status::internal(format!("get_zone_detail_by_vni failed: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                let res = dhcp.delete_zone(zone.name).await;
                let result = match res {
                    Ok(_) => ResponseResult {
                        r#type:  ResponseType::Ok as i32,
                        message: "Zone deleted successfully".into(),
                    },
                    Err(e) => ResponseResult {
                        r#type:  ResponseType::Err as i32,
                        message: format!("Failed to delete zone: {e}"),
                    },
                };
                Ok(result)
            })
            .await
            .map_err(|e| Status::internal(format!("DHCP operation failed: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        Ok(Response::new(DeletePcGroupResponse { result: Some(result) }))
    }

    async fn get_roles(
        &self,
        request: Request<GetRolesRequest>,
    ) -> Result<Response<GetRolesResponse>, Status> {
        todo!()
    }

    async fn get_role_users(
        &self,
        request: Request<GetRoleUsersRequest>,
    ) -> Result<Response<GetRoleUsersResponse>, Status> {
        todo!()
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        todo!()
    }

    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        todo!()
    }

    async fn put_role_members(
        &self,
        request: Request<PutRoleMembersRequest>,
    ) -> Result<Response<PutRoleMembersResponse>, Status> {
        todo!()
    }

    async fn patch_role(
        &self,
        request: Request<PatchRoleRequest>,
    ) -> Result<Response<PatchRoleResponse>, Status> {
        todo!()
    }

    async fn get_modules(
        &self,
        request: Request<GetModulesRequest>,
    ) -> Result<Response<GetModulesResponse>, Status> {
        todo!()
    }

    async fn upload_modules(
        &self,
        request: Request<UploadModulesRequest>,
    ) -> Result<Response<UploadModulesResponse>, Status> {
        todo!()
    }

    async fn update_modules(
        &self,
        request: Request<UpdateModulesRequest>,
    ) -> Result<Response<UpdateModulesResponse>, Status> {
        todo!()
    }

    async fn patch_module_settings(
        &self,
        request: Request<PatchModuleSettingsRequest>,
    ) -> Result<Response<PatchModuleSettingsResponse>, Status> {
        todo!()
    }

    async fn delete_modules(
        &self,
        request: Request<DeleteModulesRequest>,
    ) -> Result<Response<DeleteModulesResponse>, Status> {
        todo!()
    }

    async fn enable_modules(
        &self,
        request: Request<EnableModulesRequest>,
    ) -> Result<Response<EnableModulesResponse>, Status> {
        todo!()
    }

    async fn disable_modules(
        &self,
        request: Request<DisableModulesRequest>,
    ) -> Result<Response<DisableModulesResponse>, Status> {
        todo!()
    }

    async fn get_ip_access(
        &self,
        request: Request<GetIpAccessRequest>,
    ) -> Result<Response<GetIpAccessResponse>, Status> {
        todo!()
    }

    async fn post_ip(
        &self,
        request: Request<PostIpRequest>,
    ) -> Result<Response<PostIpResponse>, Status> {
        todo!()
    }

    async fn delete_ip(
        &self,
        request: Request<DeleteIpRequest>,
    ) -> Result<Response<DeleteIpResponse>, Status> {
        todo!()
    }

    async fn put_ip_mode(
        &self,
        request: Request<PutIpModeRequest>,
    ) -> Result<Response<PutIpModeResponse>, Status> {
        todo!()
    }

    async fn get_setting_values(
        &self,
        request: Request<GetSettingValuesRequest>,
    ) -> Result<Response<GetSettingValuesResponse>, Status> {
        let _ = request;
        let thresholds = GlobalConfig::with(|cfg| cfg.extend.info_thresholds.clone());
        let values = Values {
            cpu_usage:  Some(threshold_to_metric_setting(&thresholds.cpu)),
            disk_usage: Some(threshold_to_metric_setting(&thresholds.disk)),
            memory:     Some(threshold_to_metric_setting(&thresholds.memory)),
        };
        Ok(Response::new(GetSettingValuesResponse { values: Some(values) }))
    }

    async fn put_setting_values(
        &self,
        request: Request<PutSettingValuesRequest>,
    ) -> Result<Response<PutSettingValuesResponse>, Status> {
        let req = request.into_inner();
        let mut thresholds = GlobalConfig::with(|cfg| cfg.extend.info_thresholds.clone());
        let mut changed = false;

        if let Some(cpu) = req.cpu_usage {
            thresholds.cpu =
                metric_setting_to_threshold(&cpu).map_err(Status::invalid_argument)?;
            changed = true;
        }
        if let Some(disk) = req.disk_usage {
            thresholds.disk =
                metric_setting_to_threshold(&disk).map_err(Status::invalid_argument)?;
            changed = true;
        }
        if let Some(memory) = req.memory {
            thresholds.memory =
                metric_setting_to_threshold(&memory).map_err(Status::invalid_argument)?;
            changed = true;
        }

        if !changed {
            return Err(Status::invalid_argument("No setting values provided"));
        }

        GlobalConfig::update_with(|cfg| {
            cfg.extend.info_thresholds = thresholds.clone();
        });
        GlobalConfig::save_config()
            .await
            .map_err(|e| Status::internal(format!("Failed to save config: {e}")))?;
        GlobalConfig::send_reload();

        let resp = PutSettingValuesResponse {
            r#type:  put_setting_values_response::ResultType::Ok as i32,
            message: "Setting values updated".to_string(),
        };
        Ok(Response::new(resp))
    }

    async fn get_users(
        &self,
        request: Request<GetUsersRequest>,
    ) -> Result<Response<GetUsersResponse>, Status> {
        let users = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                let uids = ldap
                    .list_users()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list users: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                let mut users: HashMap<String, UserEntry> = HashMap::new();
                for uid in uids {
                    match ldap.search_user(uid.clone()).await {
                        Ok(detail) => {
                            let gid_number = detail.gid_number;
                            let mut group_names = Vec::new();
                            let mut primary_gid = String::new();
                            for gid in &gid_number {
                                let group_name = ldap
                                    .get_group_name(gid.clone())
                                    .await
                                    .map_err(|e| Status::not_found(e.to_string()))?
                                    .group_name;
                                if group_name == detail.uid {
                                    primary_gid = gid.clone();
                                }
                                group_names.push(group_name);
                            }
                            let entry = UserEntry {
                                username:       detail.uid,
                                password:       "".to_string(),
                                cn:             detail.cn,
                                sn:             detail.sn,
                                home_directory: detail.home_directory,
                                shell:          detail.login_shell,
                                given_name:     detail.given_name,
                                display_name:   detail.display_name,
                                gid_number:     primary_gid,
                                group:          detail.groups,
                                gecos:          detail.gecos,
                            };
                            users.insert(uid, entry);
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch details for user {uid}: {e}");
                            continue;
                        }
                    }
                }
                Ok(users)
            })
            .await
            .map_err(|e| Status::internal(format!("Ldap Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let length = users.len() as u64;
        let resp = GetUsersResponse { users, length };
        Ok(Response::new(resp))
    }

    // TODO: 添加home directory與shell的預設值
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();
        let user = req
            .user
            .ok_or_else(|| Status::invalid_argument("User field is required"))
            .inspect_err(|e| tracing::error!(?e))?;
        let username = user.username.clone();
        let username_clone = username.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if !user.group.is_empty() {
                    for group_name in user.group.iter() {
                        if group_name == &username_clone {
                            continue;
                        }
                        ldap.search_group(group_name.clone())
                            .await
                            .map_err(|e| {
                                Status::not_found(format!("Group {group_name} not found: {e}"))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                    }
                }
                ldap.add_user(
                    username_clone.clone(),
                    user.password,
                    Some(user.cn),
                    Some(user.sn),
                    Some(user.home_directory),
                    Some(user.shell),
                    Some(user.given_name),
                    Some(user.display_name),
                    Some(user.gid_number),
                    Some(user.gecos),
                )
                .await
                .inspect_err(|e| tracing::error!(?e))?;
                for group_name in user.group.iter() {
                    if group_name == &username_clone {
                        continue;
                    }
                    ldap.add_user_to_group(username_clone.clone(), group_name.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to add user {username_clone} to group {group_name}: {e}"
                            ))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功建立"),
        };
        Ok(Response::new(CreateUserResponse { result: Some(result) }))
    }

    async fn put_users(
        &self,
        request: Request<PutUsersRequest>,
    ) -> Result<Response<PutUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;
        let username = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                if users.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one user entry is required").into()
                    );
                }
                let (username, user) = users
                    .iter()
                    .next()
                    .ok_or_else(|| Status::invalid_argument("At least one user entry is required"))
                    .inspect_err(|e| tracing::error!(?e))?;
                ldap.search_user(username.clone())
                    .await
                    .map_err(|e| Status::not_found(format!("User {username} not found: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                if !user.group.is_empty() {
                    for group_name in user.group.iter() {
                        if group_name == username {
                            continue;
                        }
                        if let Err(e) = ldap.search_group(group_name.clone()).await {
                            return Err(Status::not_found(format!(
                                "Group {group_name} not found: {e}"
                            ))
                            .into());
                        }
                    }
                }
                let mut attr: HashMap<String, String> = HashMap::new();
                attr.insert("userPassword".into(), user.password.clone());
                attr.insert("cn".into(), user.cn.clone());
                attr.insert("sn".into(), user.sn.clone());
                attr.insert("homeDirectory".into(), user.home_directory.clone());
                attr.insert("loginShell".into(), user.shell.clone());
                attr.insert("givenName".into(), user.given_name.clone());
                attr.insert("displayName".into(), user.display_name.clone());
                attr.insert("gecos".into(), user.gecos.clone());
                ldap.modify_user(username.clone(), attr)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to modify user {username}: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;

                for group_name in user.group.iter() {
                    if group_name == username {
                        continue;
                    }
                    ldap.add_user_to_group(username.clone(), group_name.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to add user {username} to group {group_name}: {e}"
                            ))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                }
                Ok(username.clone())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;

        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功更新"),
        };

        Ok(Response::new(PutUsersResponse { result: Some(result) }))
    }

    // async fn patch_users(
    //     &self,
    //     request: Request<PatchUsersRequest>,
    // ) -> Result<Response<PatchUsersResponse>, Status> {
    //     dbg!(&request);
    //     let req = request.into_inner();
    //     let users = req.users;
    //     let username = self
    //         .grpc_clients
    //         .with_ldap_handle(|ldap| async move {
    //             if users.is_empty() {
    //                 return Err(
    //                     Status::invalid_argument("At least one user entry is
    // required").into()                 );
    //             }
    //             let (username, user) = users
    //                 .iter()
    //                 .next()
    //                 .ok_or_else(|| Status::invalid_argument("At least one user
    // entry is required"))                 .inspect_err(|e|
    // tracing::error!(?e))?;

    //             if let Err(e) = ldap.search_user(username.clone()).await {
    //                 return Err(Status::not_found(format!("User {username} not
    // found: {e}")).into());             }
    //             let mut attr: HashMap<String, String> = HashMap::new();
    //             if let Some(u) = &user.password {
    //                 attr.insert("userPassword".into(), u.clone());
    //             }
    //             if let Some(u) = &user.cn {
    //                 attr.insert("cn".into(), u.clone());
    //             }
    //             if let Some(u) = &user.sn {
    //                 attr.insert("sn".into(), u.clone());
    //             }
    //             if let Some(u) = &user.home_directory {
    //                 attr.insert("homeDirectory".into(), u.clone());
    //             }
    //             if let Some(u) = &user.shell {
    //                 attr.insert("loginShell".into(), u.clone());
    //             }
    //             if let Some(u) = &user.given_name {
    //                 attr.insert("givenName".into(), u.clone());
    //             }
    //             if let Some(u) = &user.display_name {
    //                 attr.insert("displayName".into(), u.clone());
    //             }
    //             if let Some(u) = &user.gecos {
    //                 attr.insert("gecos".into(), u.clone());
    //             }
    //             if !user.group.is_empty() {
    //                 for group_name in user.group.iter() {
    //                     if group_name == username {
    //                         continue;
    //                     }
    //                     if let Err(e) =
    // ldap.search_group(group_name.clone()).await {
    // return Err(Status::not_found(format!(                             "Group
    // {group_name} not found: {e}"                         ))
    //                         .into());
    //                     }
    //                 }
    //             }
    //             ldap.modify_user(username.clone(), attr)
    //                 .await
    //                 .map_err(|e| Status::internal(format!("Failed to modify user
    // {username}: {e}")))                 .inspect_err(|e|
    // tracing::error!(?e))?;             Ok(username.clone())
    //         })
    //         .await
    //         .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
    //         .inspect_err(|e| tracing::error!(?e))?;
    //     let result = ResponseResult {
    //         r#type: ResponseType::Ok as i32,
    //         message: format!("使用者 {username} 已成功更新"),
    //     };
    //     Ok(Response::new(PatchUsersResponse { result: Some(result) }))
    // }

    async fn patch_users(
        &self,
        request: Request<PatchUsersRequest>,
    ) -> Result<Response<PatchUsersResponse>, Status> {
        let req = request.into_inner();
        let users = req.users;

        let username = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                if users.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one user entry is required").into()
                    );
                }

                let (username, user) = users
                    .iter()
                    .next()
                    .ok_or_else(|| Status::invalid_argument("At least one user entry is required"))
                    .inspect_err(|e| tracing::error!(?e))?;

                let detail = ldap
                    .search_user(username.clone())
                    .await
                    .map_err(|e| Status::not_found(format!("User {username} not found: {e}")))?;
                let mut attr: HashMap<String, String> = HashMap::new();
                if let Some(u) = &user.password {
                    attr.insert("userPassword".into(), u.clone());
                }
                if let Some(u) = &user.cn {
                    attr.insert("cn".into(), u.clone());
                }
                if let Some(u) = &user.sn {
                    attr.insert("sn".into(), u.clone());
                }
                if let Some(u) = &user.home_directory {
                    attr.insert("homeDirectory".into(), u.clone());
                }
                if let Some(u) = &user.shell {
                    attr.insert("loginShell".into(), u.clone());
                }
                if let Some(u) = &user.given_name {
                    attr.insert("givenName".into(), u.clone());
                }
                if let Some(u) = &user.display_name {
                    attr.insert("displayName".into(), u.clone());
                }
                if let Some(u) = &user.gecos {
                    attr.insert("gecos".into(), u.clone());
                }
                use std::collections::HashSet;
                let current_groups: HashSet<String> = detail
                    .groups
                    .into_iter()
                    .filter(|g| g != username) // 跳過同名 UPG 群組
                    .collect();
                let desired_groups_iter = user
                    .group
                    .iter()
                    .filter(|g| *g != username) // 一樣跳過 UPG
                    .cloned();
                let mut desired_groups = HashSet::new();
                for group_name in desired_groups_iter {
                    if let Err(e) = ldap.search_group(group_name.clone()).await {
                        return Err(Status::not_found(format!(
                            "Group {group_name} not found: {e}"
                        ))
                        .into());
                    }
                    desired_groups.insert(group_name);
                }
                let to_add: Vec<String> =
                    desired_groups.difference(&current_groups).cloned().collect();
                let to_remove: Vec<String> =
                    current_groups.difference(&desired_groups).cloned().collect();
                ldap.modify_user(username.clone(), attr)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to modify user {username}: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;

                for group_name in to_add {
                    ldap.add_user_to_group(username.clone(), group_name.clone()).await.map_err(
                        |e| {
                            Status::internal(format!(
                                "Failed to add {username} to group {group_name}: {e}"
                            ))
                        },
                    )?;
                }
                for group_name in to_remove {
                    ldap.remove_user_from_group(username.clone(), group_name.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to remove {username} from group {group_name}: {e}"
                            ))
                        })?;
                }

                Ok(username.clone())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;

        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("使用者 {username} 已成功更新"),
        };
        Ok(Response::new(PatchUsersResponse { result: Some(result) }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();
        let uid = req.uid;
        let uid_clone = uid.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                ldap.search_user(uid_clone.clone()).await.inspect_err(|e| {
                    tracing::warn!(uid = uid_clone, ?e, "User not found when deleting");
                })?;
                ldap.remove_user_from_all_groups_and_web_roles(&uid_clone).await.inspect_err(
                    |e| {
                        tracing::error!(
                            uid = uid_clone,
                            ?e,
                            "Failed to remove user from all groups/web roles"
                        );
                    },
                )?;
                ldap.delete_user(uid_clone.clone()).await.inspect_err(|e| {
                    tracing::error!(uid = uid_clone, ?e, "Failed to delete user");
                })?;
                Ok(())
            })
            .await
            .map_err(|e| {
                tracing::error!(uid = uid, ?e, "LDAP handle error when deleting user");
                Status::internal(format!("LDAP Error: {e}"))
            })?;

        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("使用者 {uid} 已成功刪除"),
        };

        Ok(Response::new(DeleteUserResponse { result: Some(result) }))
    }

    async fn get_groups(
        &self,
        request: Request<GetGroupsRequest>,
    ) -> Result<Response<GetGroupsResponse>, Status> {
        let groups = self
            .grpc_clients
            .with_ldap_handle(|ldap| async move {
                let gids = ldap
                    .list_groups()
                    .await
                    .map_err(|e| Status::internal(format!("Failed to list groups: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                let mut groups: HashMap<String, GroupInfo> = HashMap::new();
                for gid in gids {
                    match ldap.search_group(gid.clone()).await {
                        Ok(detail) => {
                            let entry =
                                GroupInfo { groupname: detail.cn, users: detail.member_uid };
                            groups.insert(gid, entry);
                        }
                        Err(e) => {
                            eprintln!("Failed to fetch details for group {gid}: {e}");
                            continue;
                        }
                    }
                }
                Ok(groups)
            })
            .await
            .map_err(|e| Status::internal(format!("Ldap Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let resp = GetGroupsResponse { groups };
        Ok(Response::new(resp))
    }

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let req = request.into_inner();
        let groupname = req.groupname.clone();
        let users = req.users.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                ldap.add_group(groupname.clone())
                    .await
                    .map_err(|e| Status::internal(format!("Failed to add group {groupname}: {e}")))
                    .inspect_err(|e| tracing::error!(?e))?;
                for uid in users {
                    ldap.add_user_to_group(uid.clone(), groupname.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to add user {uid} to group {groupname}: {e}"
                            ))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("群組 {} 已成功建立", req.groupname),
        };
        Ok(Response::new(CreateGroupResponse { result: Some(result) }))
    }

    async fn put_groups(
        &self,
        request: Request<PutGroupsRequest>,
    ) -> Result<Response<PutGroupsResponse>, Status> {
        let req = request.into_inner();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                for (old_name, group_info) in req.groups.iter() {
                    let new_name = &group_info.groupname;

                    let group_exists = ldap
                        .search_group(new_name.clone())
                        .await
                        .map(|_| true)
                        .or_else(|_| Ok(false))
                        .map_err(|e: Box<dyn std::error::Error + Send + Sync>| {
                            Status::internal(format!("LDAP search error: {e}"))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                    if old_name != new_name {
                        ldap.modify_group_name(old_name.clone(), new_name.clone())
                            .await
                            .map_err(|e| {
                                Status::internal(format!(
                                    "Failed to rename group {old_name} -> {new_name}: {e}"
                                ))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                    }
                    let current_users: Vec<String> = ldap
                        .list_user_in_group(new_name.clone())
                        .await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to list users in group {new_name}: {e}"
                            ))
                        })
                        .inspect_err(|e| tracing::error!(?e))?;
                    let new_users: HashSet<_> = group_info.users.iter().cloned().collect();
                    let current_users_set: HashSet<_> = current_users.into_iter().collect();
                    for uid in new_users.difference(&current_users_set) {
                        ldap.search_user(uid.clone())
                            .await
                            .map_err(|e| Status::not_found(format!("User {uid} not found: {e}")))
                            .inspect_err(|e| tracing::error!(?e))?;
                        ldap.add_user_to_group(uid.clone(), new_name.clone())
                            .await
                            .map_err(|e| {
                                Status::internal(format!(
                                    "Failed to add user {uid} to group {new_name}: {e}"
                                ))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                    }
                    for uid in current_users_set.difference(&new_users) {
                        ldap.remove_user_from_group(uid.clone(), new_name.clone())
                            .await
                            .map_err(|e| {
                                Status::internal(format!(
                                    "Failed to remove user {uid} from group {new_name}: {e}"
                                ))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: "群組資料已成功更新".to_string(),
        };
        Ok(Response::new(PutGroupsResponse { result: Some(result) }))
    }

    async fn patch_groups(
        &self,
        request: Request<PatchGroupsRequest>,
    ) -> Result<Response<PatchGroupsResponse>, Status> {
        let req = request.into_inner();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if req.groups.is_empty() {
                    return Err(
                        Status::invalid_argument("At least one group entry is required").into()
                    );
                }
                for (old_name, patch_info) in req.groups.iter() {
                    if let Some(new_name) = &patch_info.groupname {
                        if old_name != new_name {
                            let group_exists = ldap
                                .search_group(new_name.clone())
                                .await
                                .map(|_| true)
                                .or_else(|_| Ok(false))
                                .map_err(|e: Box<dyn std::error::Error + Send + Sync>| {
                                    Status::internal(format!("LDAP search error: {e}"))
                                })
                                .inspect_err(|e| tracing::error!(?e))?;
                            if group_exists {
                                return Err(Status::already_exists(format!(
                                    "Group '{new_name}' already exists"
                                ))
                                .into());
                            }
                            ldap.modify_group_name(old_name.clone(), new_name.clone())
                                .await
                                .map_err(|e| {
                                    Status::internal(format!(
                                        "Failed to rename group {old_name} -> {new_name}: {e}"
                                    ))
                                })
                                .inspect_err(|e| tracing::error!(?e))?;
                        }
                    }
                    if !patch_info.users.is_empty() {
                        let users = &patch_info.users;
                        let group_name = patch_info.groupname.as_ref().unwrap_or(old_name);
                        let current_users = ldap
                            .list_user_in_group(group_name.clone())
                            .await
                            .map_err(|e| {
                                Status::internal(format!(
                                    "Failed to list users in group {group_name}: {e}"
                                ))
                            })
                            .inspect_err(|e| tracing::error!(?e))?;
                        let current_set: HashSet<_> = current_users.into_iter().collect();
                        let new_set: HashSet<_> = users.iter().cloned().collect();
                        for uid in new_set.difference(&current_set) {
                            ldap.add_user_to_group(uid.clone(), group_name.clone())
                                .await
                                .map_err(|e| {
                                    Status::internal(format!("Failed to add user {uid}: {e}"))
                                })
                                .inspect_err(|e| tracing::error!(?e))?;
                        }
                        for uid in current_set.difference(&new_set) {
                            ldap.remove_user_from_group(uid.clone(), group_name.clone())
                                .await
                                .map_err(|e| {
                                    Status::internal(format!("Failed to remove user {uid}: {e}"))
                                })
                                .inspect_err(|e| tracing::error!(?e))?;
                        }
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: "群組已成功更新".to_string(),
        };
        Ok(Response::new(PatchGroupsResponse { result: Some(result) }))
    }

    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let req = request.into_inner();
        let group_name = req.gid;
        let group_name_clone = group_name.clone();
        self.grpc_clients
            .with_ldap_handle(|ldap| async move {
                if let Err(e) = ldap.search_group(group_name_clone.clone()).await {
                    return Err(Status::not_found(format!(
                        "Group {group_name_clone} not found: {e}"
                    ))
                    .into());
                }
                ldap.delete_group(group_name_clone.clone())
                    .await
                    .map_err(|e| {
                        Status::internal(format!("Failed to delete group {group_name_clone}: {e}"))
                    })
                    .inspect_err(|e| tracing::error!(?e))?;
                Ok(())
            })
            .await
            .map_err(|e| Status::internal(format!("LDAP Error: {e}")))
            .inspect_err(|e| tracing::error!(?e))?;
        let result = ResponseResult {
            r#type:  ResponseType::Ok as i32,
            message: format!("群組 {group_name} 已成功刪除"),
        };
        Ok(Response::new(DeleteGroupResponse { result: Some(result) }))
    }

    async fn get_cron_jobs(
        &self,
        request: Request<GetCronJobsRequest>,
    ) -> Result<Response<GetCronJobsResponse>, Status> {
        todo!()
    }

    async fn create_cron(
        &self,
        request: Request<CreateCronRequest>,
    ) -> Result<Response<CreateCronResponse>, Status> {
        todo!()
    }

    async fn delete_cron(
        &self,
        request: Request<DeleteCronRequest>,
    ) -> Result<Response<DeleteCronResponse>, Status> {
        todo!()
    }

    async fn put_cron(
        &self,
        request: Request<PutCronRequest>,
    ) -> Result<Response<PutCronResponse>, Status> {
        todo!()
    }

    async fn import_cron(
        &self,
        request: Request<ImportCronRequest>,
    ) -> Result<Response<ImportCronResponse>, Status> {
        todo!()
    }

    async fn export_cron(
        &self,
        request: Request<ExportCronRequest>,
    ) -> Result<Response<ExportCronResponse>, Status> {
        todo!()
    }

    async fn get_pdir_pcs(
        &self,
        request: Request<GetPdirPcsRequest>,
    ) -> Result<Response<GetPdirPcsResponse>, Status> {
        todo!()
    }

    async fn get_pdir_one(
        &self,
        request: Request<GetPdirOneRequest>,
    ) -> Result<Response<GetPdirOneResponse>, Status> {
        todo!()
    }

    async fn upload_pdir_files(
        &self,
        request: Request<UploadPdirFilesRequest>,
    ) -> Result<Response<UploadPdirFilesResponse>, Status> {
        todo!()
    }

    async fn download_pdir_file(
        &self,
        request: Request<DownloadPdirFileRequest>,
    ) -> Result<Response<DownloadPdirFileResponse>, Status> {
        todo!()
    }

    async fn get_vdir_path(
        &self,
        request: Request<GetVdirPathRequest>,
    ) -> Result<Response<GetVdirPathResponse>, Status> {
        todo!()
    }

    async fn upload_vdir_files(
        &self,
        request: Request<UploadVdirFilesRequest>,
    ) -> Result<Response<UploadVdirFilesResponse>, Status> {
        todo!()
    }

    async fn download_vdir_file(
        &self,
        request: Request<DownloadVdirFileRequest>,
    ) -> Result<Response<DownloadVdirFileResponse>, Status> {
        todo!()
    }

    async fn get_sys_logs(
        &self,
        request: Request<GetSysLogsRequest>,
    ) -> Result<Response<GetSysLogsResponse>, Status> {
        todo!()
    }

    async fn query_sys_logs(
        &self,
        request: Request<QuerySysLogsRequest>,
    ) -> Result<Response<QuerySysLogsResponse>, Status> {
        todo!()
    }

    async fn get_pc_log_pcs(
        &self,
        request: Request<GetPcLogPcsRequest>,
    ) -> Result<Response<GetPcLogPcsResponse>, Status> {
        todo!()
    }

    async fn get_pc_logs(
        &self,
        request: Request<GetPcLogsRequest>,
    ) -> Result<Response<GetPcLogsResponse>, Status> {
        todo!()
    }

    async fn query_pc_logs(
        &self,
        request: Request<QueryPcLogsRequest>,
    ) -> Result<Response<QueryPcLogsResponse>, Status> {
        todo!()
    }

    async fn get_firewall_pcs(
        &self,
        request: Request<GetFirewallPcsRequest>,
    ) -> Result<Response<GetFirewallPcsResponse>, Status> {
        todo!()
    }

    async fn get_firewall(
        &self,
        request: Request<GetFirewallRequest>,
    ) -> Result<Response<GetFirewallResponse>, Status> {
        todo!()
    }

    async fn add_firewall_rule(
        &self,
        request: Request<AddFirewallRuleRequest>,
    ) -> Result<Response<AddFirewallRuleResponse>, Status> {
        todo!()
    }

    async fn delete_firewall_rule(
        &self,
        request: Request<DeleteFirewallRuleRequest>,
    ) -> Result<Response<DeleteFirewallRuleResponse>, Status> {
        todo!()
    }

    async fn put_firewall_status(
        &self,
        request: Request<PutFirewallStatusRequest>,
    ) -> Result<Response<PutFirewallStatusResponse>, Status> {
        todo!()
    }

    async fn put_firewall_policy(
        &self,
        request: Request<PutFirewallPolicyRequest>,
    ) -> Result<Response<PutFirewallPolicyResponse>, Status> {
        todo!()
    }

    async fn get_all_net(
        &self,
        request: Request<GetAllNetRequest>,
    ) -> Result<Response<GetAllNetResponse>, Status> {
        todo!()
    }

    async fn create_net(
        &self,
        request: Request<CreateNetRequest>,
    ) -> Result<Response<CreateNetResponse>, Status> {
        todo!()
    }

    async fn delete_net(
        &self,
        request: Request<DeleteNetRequest>,
    ) -> Result<Response<DeleteNetResponse>, Status> {
        todo!()
    }

    async fn patch_net(
        &self,
        request: Request<PatchNetRequest>,
    ) -> Result<Response<PatchNetResponse>, Status> {
        todo!()
    }

    async fn put_net(
        &self,
        request: Request<PutNetRequest>,
    ) -> Result<Response<PutNetResponse>, Status> {
        todo!()
    }

    async fn net_up(
        &self,
        request: Request<NetUpRequest>,
    ) -> Result<Response<NetUpResponse>, Status> {
        todo!()
    }

    async fn net_down(
        &self,
        request: Request<NetDownRequest>,
    ) -> Result<Response<NetDownResponse>, Status> {
        todo!()
    }

    async fn get_all_route(
        &self,
        request: Request<GetAllRouteRequest>,
    ) -> Result<Response<GetAllRouteResponse>, Status> {
        todo!()
    }

    async fn create_route(
        &self,
        request: Request<CreateRouteRequest>,
    ) -> Result<Response<CreateRouteResponse>, Status> {
        todo!()
    }

    async fn delete_route(
        &self,
        request: Request<DeleteRouteRequest>,
    ) -> Result<Response<DeleteRouteResponse>, Status> {
        todo!()
    }

    async fn patch_route(
        &self,
        request: Request<PatchRouteRequest>,
    ) -> Result<Response<PatchRouteResponse>, Status> {
        todo!()
    }

    async fn put_route(
        &self,
        request: Request<PutRouteRequest>,
    ) -> Result<Response<PutRouteResponse>, Status> {
        todo!()
    }

    async fn get_all_dns(
        &self,
        request: Request<GetAllDnsRequest>,
    ) -> Result<Response<GetAllDnsResponse>, Status> {
        todo!()
    }

    async fn patch_hostname(
        &self,
        request: Request<PatchHostnameRequest>,
    ) -> Result<Response<PatchHostnameResponse>, Status> {
        todo!()
    }

    async fn put_dns(
        &self,
        request: Request<PutDnsRequest>,
    ) -> Result<Response<PutDnsResponse>, Status> {
        todo!()
    }

    async fn get_all_process(
        &self,
        request: Request<GetAllProcessRequest>,
    ) -> Result<Response<GetAllProcessResponse>, Status> {
        todo!()
    }

    async fn get_one_process(
        &self,
        request: Request<GetOneProcessRequest>,
    ) -> Result<Response<GetOneProcessResponse>, Status> {
        todo!()
    }

    async fn start_process(
        &self,
        request: Request<StartProcessRequest>,
    ) -> Result<Response<StartProcessResponse>, Status> {
        todo!()
    }

    async fn stop_process(
        &self,
        request: Request<StopProcessRequest>,
    ) -> Result<Response<StopProcessResponse>, Status> {
        todo!()
    }

    async fn restart_process(
        &self,
        request: Request<RestartProcessRequest>,
    ) -> Result<Response<RestartProcessResponse>, Status> {
        todo!()
    }

    async fn enable_process(
        &self,
        request: Request<EnableProcessRequest>,
    ) -> Result<Response<EnableProcessResponse>, Status> {
        todo!()
    }

    async fn disable_process(
        &self,
        request: Request<DisableProcessRequest>,
    ) -> Result<Response<DisableProcessResponse>, Status> {
        todo!()
    }

    async fn start_enable_process(
        &self,
        request: Request<StartEnableProcessRequest>,
    ) -> Result<Response<StartEnableProcessResponse>, Status> {
        todo!()
    }

    async fn stop_disable_process(
        &self,
        request: Request<StopDisableProcessRequest>,
    ) -> Result<Response<StopDisableProcessResponse>, Status> {
        todo!()
    }

    async fn get_software(
        &self,
        request: Request<GetSoftwareRequest>,
    ) -> Result<Response<GetSoftwareResponse>, Status> {
        let _ = request.into_inner();
        let agents: Vec<ServiceDescriptor> = GlobalConfig::with(|cfg| {
            cfg.extend
                .services_pool
                .services
                .iter()
                .flat_map(|entry| {
                    entry.value().clone().into_iter().filter(|svc| svc.kind == ServiceKind::Agent)
                })
                .collect()
        });
        let mut pcs = HashMap::new();
        for agent in agents {
            let uuid = agent.uuid.to_string();
            match self.fetch_software_inventory(&uuid).await {
                Ok(pkgs) => {
                    pcs.insert(uuid, pkgs);
                }
                Err(err) => {
                    tracing::warn!(%uuid, "failed to fetch software inventory: {err}");
                }
            }
        }
        Ok(Response::new(GetSoftwareResponse { pcs }))
    }

    async fn install_software(
        &self,
        request: Request<InstallSoftwareRequest>,
    ) -> Result<Response<PackageActionResponse>, Status> {
        let req = request.into_inner();
        if req.uuids.is_empty() {
            return Err(Status::invalid_argument("至少需要指定一台主機"));
        }
        if req.packages.is_empty() {
            return Err(Status::invalid_argument("至少需要指定一個套件"));
        }
        let packages = req.packages;
        let uuids = req.uuids;
        let payload = json!({ "Packages": packages.clone() }).to_string();
        let mut results = Self::init_package_result_map(&packages);
        for uuid in uuids {
            let parsed_uuid = match Uuid::parse_str(&uuid) {
                Ok(uuid) => uuid,
                Err(_) => {
                    tracing::warn!(%uuid, "software install skipped: invalid uuid");
                    Self::record_action_result(&mut results, &uuid, false, true);
                    continue;
                }
            };
            if !Self::agent_exists(&parsed_uuid) {
                tracing::warn!(%uuid, "software install skipped: unknown agent");
                Self::record_action_result(&mut results, &uuid, false, true);
                continue;
            }
            match self
                .run_software_action(&uuid, AgentCommand::SoftwareInstall, Some(payload.clone()))
                .await
            {
                Ok(_) => Self::record_action_result(&mut results, &uuid, true, true),
                Err(err) => {
                    tracing::warn!(%uuid, "software install failed: {err}");
                    Self::record_action_result(&mut results, &uuid, false, true);
                }
            }
        }
        let length = results.len() as u64;
        Ok(Response::new(PackageActionResponse { packages: results, length }))
    }

    async fn delete_software(
        &self,
        request: Request<DeleteSoftwareRequest>,
    ) -> Result<Response<PackageActionResponse>, Status> {
        let req = request.into_inner();
        if req.uuids.is_empty() {
            return Err(Status::invalid_argument("至少需要指定一台主機"));
        }
        if req.packages.is_empty() {
            return Err(Status::invalid_argument("至少需要指定一個套件"));
        }
        let packages = req.packages;
        let uuids = req.uuids;
        let payload = json!({ "Package": packages.clone() }).to_string();
        let mut results = Self::init_package_result_map(&packages);
        for uuid in uuids {
            let parsed_uuid = match Uuid::parse_str(&uuid) {
                Ok(uuid) => uuid,
                Err(_) => {
                    tracing::warn!(%uuid, "software delete skipped: invalid uuid");
                    Self::record_action_result(&mut results, &uuid, false, false);
                    continue;
                }
            };
            if !Self::agent_exists(&parsed_uuid) {
                tracing::warn!(%uuid, "software delete skipped: unknown agent");
                Self::record_action_result(&mut results, &uuid, false, false);
                continue;
            }
            match self
                .run_software_action(&uuid, AgentCommand::SoftwareDelete, Some(payload.clone()))
                .await
            {
                Ok(_) => Self::record_action_result(&mut results, &uuid, true, false),
                Err(err) => {
                    tracing::warn!(%uuid, "software delete failed: {err}");
                    Self::record_action_result(&mut results, &uuid, false, false);
                }
            }
        }
        let length = results.len() as u64;
        Ok(Response::new(PackageActionResponse { packages: results, length }))
    }

    async fn get_apache_status(
        &self,
        request: Request<GetApacheRequest>,
    ) -> Result<Response<GetApacheResponse>, Status> {
        let req = request.into_inner();
        let (parsed_uuid, uuid_str) = parse_agent_uuid_input(&req.uuid)?;
        if !Self::agent_exists(&parsed_uuid) {
            return Err(Status::not_found("指定的 Agent 不存在"));
        }

        let response =
            self.execute_agent_command(&uuid_str, AgentCommand::GetServerApache, None).await?;
        let info = extract_apache_info(response)?;
        let converted = convert_agent_apache_info(info)?;
        Ok(Response::new(converted))
    }

    async fn start_apache(
        &self,
        request: Request<StartApacheRequest>,
    ) -> Result<Response<StartApacheResponse>, Status> {
        let req = request.into_inner();
        let inner = req
            .inner
            .ok_or_else(|| Status::invalid_argument("start_apache 需要提供 inner 內容"))?;
        let (parsed_uuid, uuid_str) = parse_apache_action_uuid(&inner.uuid, "start_apache")?;
        if !Self::agent_exists(&parsed_uuid) {
            return Err(Status::not_found("指定的 Agent 不存在"));
        }

        let response =
            self.execute_agent_command(&uuid_str, AgentCommand::ServerApacheStart, None).await?;
        let info = extract_return_info(response)?;
        let action_result = convert_return_info_to_action_result(info);
        Ok(Response::new(StartApacheResponse { result: Some(action_result) }))
    }

    async fn stop_apache(
        &self,
        request: Request<StopApacheRequest>,
    ) -> Result<Response<StopApacheResponse>, Status> {
        let req = request.into_inner();
        let inner =
            req.inner.ok_or_else(|| Status::invalid_argument("stop_apache 需要提供 inner 內容"))?;
        let (parsed_uuid, uuid_str) = parse_apache_action_uuid(&inner.uuid, "stop_apache")?;
        if !Self::agent_exists(&parsed_uuid) {
            return Err(Status::not_found("指定的 Agent 不存在"));
        }

        let response =
            self.execute_agent_command(&uuid_str, AgentCommand::ServerApacheStop, None).await?;
        let info = extract_return_info(response)?;
        let action_result = convert_return_info_to_action_result(info);
        Ok(Response::new(StopApacheResponse { result: Some(action_result) }))
    }

    async fn restart_apache(
        &self,
        request: Request<RestartApacheRequest>,
    ) -> Result<Response<RestartApacheResponse>, Status> {
        let req = request.into_inner();
        let inner = req
            .inner
            .ok_or_else(|| Status::invalid_argument("restart_apache 需要提供 inner 內容"))?;
        let (parsed_uuid, uuid_str) = parse_apache_action_uuid(&inner.uuid, "restart_apache")?;
        if !Self::agent_exists(&parsed_uuid) {
            return Err(Status::not_found("指定的 Agent 不存在"));
        }

        let response =
            self.execute_agent_command(&uuid_str, AgentCommand::ServerApacheRestart, None).await?;
        let info = extract_return_info(response)?;
        let action_result = convert_return_info_to_action_result(info);
        Ok(Response::new(RestartApacheResponse { result: Some(action_result) }))
    }

    async fn get_bind_status(
        &self,
        request: Request<GetBindRequest>,
    ) -> Result<Response<GetBindResponse>, Status> {
        todo!()
    }

    async fn start_bind(
        &self,
        request: Request<StartBindRequest>,
    ) -> Result<Response<StartBindResponse>, Status> {
        todo!()
    }

    async fn stop_bind(
        &self,
        request: Request<StopBindRequest>,
    ) -> Result<Response<StopBindResponse>, Status> {
        todo!()
    }

    async fn restart_bind(
        &self,
        request: Request<RestartBindRequest>,
    ) -> Result<Response<RestartBindResponse>, Status> {
        todo!()
    }

    async fn get_ldap_status(
        &self,
        request: Request<GetLdapRequest>,
    ) -> Result<Response<GetLdapResponse>, Status> {
        todo!()
    }

    async fn start_ldap(
        &self,
        request: Request<StartLdapRequest>,
    ) -> Result<Response<StartLdapResponse>, Status> {
        todo!()
    }

    async fn stop_ldap(
        &self,
        request: Request<StopLdapRequest>,
    ) -> Result<Response<StopLdapResponse>, Status> {
        todo!()
    }

    async fn restart_ldap(
        &self,
        request: Request<RestartLdapRequest>,
    ) -> Result<Response<RestartLdapResponse>, Status> {
        todo!()
    }

    async fn get_my_sql_status(
        &self,
        request: Request<GetMySqlRequest>,
    ) -> Result<Response<GetMySqlResponse>, Status> {
        todo!()
    }

    async fn start_my_sql(
        &self,
        request: Request<StartMySqlRequest>,
    ) -> Result<Response<StartMySqlResponse>, Status> {
        todo!()
    }

    async fn stop_my_sql(
        &self,
        request: Request<StopMySqlRequest>,
    ) -> Result<Response<StopMySqlResponse>, Status> {
        todo!()
    }

    async fn restart_my_sql(
        &self,
        request: Request<RestartMySqlRequest>,
    ) -> Result<Response<RestartMySqlResponse>, Status> {
        todo!()
    }

    async fn get_nginx_status(
        &self,
        request: Request<GetNginxRequest>,
    ) -> Result<Response<GetNginxResponse>, Status> {
        todo!()
    }

    async fn start_nginx(
        &self,
        request: Request<StartNginxRequest>,
    ) -> Result<Response<StartNginxResponse>, Status> {
        todo!()
    }

    async fn stop_nginx(
        &self,
        request: Request<StopNginxRequest>,
    ) -> Result<Response<StopNginxResponse>, Status> {
        todo!()
    }

    async fn restart_nginx(
        &self,
        request: Request<RestartNginxRequest>,
    ) -> Result<Response<RestartNginxResponse>, Status> {
        todo!()
    }

    async fn get_ftp_status(
        &self,
        request: Request<GetFtpRequest>,
    ) -> Result<Response<GetFtpResponse>, Status> {
        todo!()
    }

    async fn start_ftp(
        &self,
        request: Request<StartFtpRequest>,
    ) -> Result<Response<StartFtpResponse>, Status> {
        todo!()
    }

    async fn stop_ftp(
        &self,
        request: Request<StopFtpRequest>,
    ) -> Result<Response<StopFtpResponse>, Status> {
        todo!()
    }

    async fn restart_ftp(
        &self,
        request: Request<RestartFtpRequest>,
    ) -> Result<Response<RestartFtpResponse>, Status> {
        todo!()
    }

    async fn get_samba_status(
        &self,
        request: Request<GetSambaRequest>,
    ) -> Result<Response<GetSambaResponse>, Status> {
        todo!()
    }

    async fn start_samba(
        &self,
        request: Request<StartSambaRequest>,
    ) -> Result<Response<StartSambaResponse>, Status> {
        todo!()
    }

    async fn stop_samba(
        &self,
        request: Request<StopSambaRequest>,
    ) -> Result<Response<StopSambaResponse>, Status> {
        todo!()
    }

    async fn restart_samba(
        &self,
        request: Request<RestartSambaRequest>,
    ) -> Result<Response<RestartSambaResponse>, Status> {
        todo!()
    }

    async fn get_server_installed_pcs(
        &self,
        request: Request<GetServerInstalledPcsRequest>,
    ) -> Result<Response<GetServerInstalledPcsResponse>, Status> {
        let req = request.into_inner();
        let server = parse_server_name_input(&req.server)?;
        let pcs = self.collect_server_hosts(&server, AgentCommand::GetServerInstall).await?;
        let length = pcs.len() as u64;
        Ok(Response::new(GetServerInstalledPcsResponse { pcs, length }))
    }

    async fn get_server_not_installed_pcs(
        &self,
        request: Request<GetServerNotInstalledPcsRequest>,
    ) -> Result<Response<GetServerNotInstalledPcsResponse>, Status> {
        let req = request.into_inner();
        let server = parse_server_name_input(&req.server)?;
        let pcs = self.collect_server_hosts(&server, AgentCommand::GetServerNoninstall).await?;
        let length = pcs.len() as u64;
        Ok(Response::new(GetServerNotInstalledPcsResponse { pcs, length }))
    }

    async fn install_server(
        &self,
        request: Request<InstallServerRequest>,
    ) -> Result<Response<InstallServerResponse>, Status> {
        let req = request.into_inner();
        let server = parse_server_name_input(&req.server)?;
        if req.uuids.is_empty() {
            return Err(Status::invalid_argument("必須提供至少一個 UUID"));
        }
        let mut success = Vec::new();
        let mut failures = Vec::new();

        for raw_uuid in req.uuids {
            let trimmed = raw_uuid.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (parsed_uuid, uuid_str) = parse_agent_uuid_input(trimmed)?;
            if !Self::agent_exists(&parsed_uuid) {
                failures.push(format!("{trimmed}: 指定的 Agent 不存在"));
                continue;
            }

            let sysinfo = match self.fetch_agent_system_info(&uuid_str).await {
                Ok(info) => info,
                Err(err) => {
                    failures.push(format!("{uuid_str}: {err}"));
                    continue;
                }
            };
            let package = match resolve_server_package(&server, &sysinfo) {
                Ok(pkg) => pkg.to_string(),
                Err(err) => {
                    failures.push(format!("{uuid_str}: {err}"));
                    continue;
                }
            };

            let payload = json!({ "Packages": [package] }).to_string();
            match self
                .run_software_action(&uuid_str, AgentCommand::SoftwareInstall, Some(payload))
                .await
            {
                Ok(_) => {
                    success.push(uuid_str);
                }
                Err(err) => {
                    failures.push(format!("{uuid_str}: {err}"));
                }
            }
        }

        let result = if failures.is_empty() {
            ActionResult {
                r#type:  action_result::Type::Ok as i32,
                message: format!("成功安裝 {server} 於 {} 台主機", success.len()),
            }
        } else {
            ActionResult {
                r#type:  action_result::Type::Err as i32,
                message: format!(
                    "{server} 安裝成功 {success_count} 台，失敗 {fail_count} 台: {detail}",
                    success_count = success.len(),
                    fail_count = failures.len(),
                    detail = failures.join("; ")
                ),
            }
        };

        Ok(Response::new(InstallServerResponse { result: Some(result) }))
    }

    async fn get_squid(
        &self,
        request: Request<GetSquidRequest>,
    ) -> Result<Response<GetSquidResponse>, Status> {
        todo!()
    }

    async fn start_squid(
        &self,
        request: Request<StartSquidRequest>,
    ) -> Result<Response<StartSquidResponse>, Status> {
        todo!()
    }

    async fn stop_squid(
        &self,
        request: Request<StopSquidRequest>,
    ) -> Result<Response<StopSquidResponse>, Status> {
        todo!()
    }

    async fn restart_squid(
        &self,
        request: Request<RestartSquidRequest>,
    ) -> Result<Response<RestartSquidResponse>, Status> {
        todo!()
    }

    async fn get_ssh(
        &self,
        request: Request<GetSshRequest>,
    ) -> Result<Response<GetSshResponse>, Status> {
        todo!()
    }

    async fn start_ssh(
        &self,
        request: Request<StartSshRequest>,
    ) -> Result<Response<StartSshResponse>, Status> {
        todo!()
    }

    async fn stop_ssh(
        &self,
        request: Request<StopSshRequest>,
    ) -> Result<Response<StopSshResponse>, Status> {
        todo!()
    }

    async fn restart_ssh(
        &self,
        request: Request<RestartSshRequest>,
    ) -> Result<Response<RestartSshResponse>, Status> {
        todo!()
    }
}

impl ControllerRestfulServer {
    fn init_package_result_map(packages: &[String]) -> HashMap<String, PackageActionResult> {
        let mut map = HashMap::new();
        for pkg in packages {
            map.entry(pkg.clone()).or_insert_with(|| PackageActionResult {
                installed:    Vec::new(),
                notinstalled: Vec::new(),
            });
        }
        map
    }

    fn record_action_result(
        results: &mut HashMap<String, PackageActionResult>,
        uuid: &str,
        success: bool,
        is_install: bool,
    ) {
        for entry in results.values_mut() {
            match (is_install, success) {
                (true, true) | (false, false) => entry.installed.push(uuid.to_string()),
                (true, false) | (false, true) => entry.notinstalled.push(uuid.to_string()),
            }
        }
    }

    async fn exec_agent_command(
        &self,
        uuid: &str,
        command: AgentCommand,
        argument: Option<String>,
    ) -> Result<agent::CommandResponse, String> {
        self.grpc_clients
            .with_agent_uuid_handle(uuid, move |agent| {
                let argument = argument.clone();
                async move {
                    let mut client = agent.get_m_client();
                    let resp = client
                        .execute_command(CommandRequest { command: command as i32, argument })
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                    Ok(resp.into_inner())
                }
            })
            .await
            .map_err(|e| e.to_string())
    }

    async fn fetch_software_inventory(&self, uuid: &str) -> Result<PcPackages, String> {
        let response = self.exec_agent_command(uuid, AgentCommand::GetSoftware, None).await?;
        match response.payload {
            Some(command_response::Payload::SoftwareInventory(inv)) => {
                Ok(Self::convert_inventory(inv))
            }
            Some(_) => Err("Agent response missing software inventory".into()),
            None => Err("Agent response missing payload".into()),
        }
    }

    async fn run_software_action(
        &self,
        uuid: &str,
        command: AgentCommand,
        argument: Option<String>,
    ) -> Result<(), String> {
        let response = self.exec_agent_command(uuid, command, argument).await?;
        match response.payload {
            Some(command_response::Payload::ReturnInfo(info)) => {
                if info.r#type.eq_ignore_ascii_case("ok") {
                    Ok(())
                } else {
                    Err(info.message)
                }
            }
            _ => Err("Agent response missing ReturnInfo".into()),
        }
    }

    async fn fetch_agent_system_info(&self, uuid: &str) -> Result<agent::SystemInfo, String> {
        let response = self.exec_agent_command(uuid, AgentCommand::GetSystemInfo, None).await?;
        match response.payload {
            Some(command_response::Payload::SystemInfo(info)) => Ok(info),
            _ => Err("Agent response missing system information".into()),
        }
    }

    fn convert_inventory(inv: agent::SoftwareInventory) -> PcPackages {
        let packages = inv
            .packages
            .into_iter()
            .map(|(name, pkg)| {
                (
                    name,
                    PackageInfo {
                        version: pkg.version,
                        status:  Self::map_agent_status(pkg.status),
                    },
                )
            })
            .collect();
        PcPackages { packages }
    }

    fn map_agent_status(status: i32) -> i32 {
        match agent::PackageStatus::try_from(status).unwrap_or(agent::PackageStatus::Unspecified) {
            agent::PackageStatus::Installed => PackageStatus::Installed as i32,
            agent::PackageStatus::Notinstall => PackageStatus::Notinstall as i32,
            agent::PackageStatus::Unspecified => PackageStatus::Notinstall as i32,
        }
    }
}
