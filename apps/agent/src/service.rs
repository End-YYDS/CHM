use std::{convert::TryFrom, sync::Arc};

use crate::{
    agent_info_structured, cron_info_structured, dns_info_structured, execute_cron_add,
    execute_cron_delete, execute_cron_update, execute_firewall_add, execute_firewall_delete,
    execute_firewall_edit_policy, execute_firewall_edit_status, execute_netif_add,
    execute_netif_delete, execute_netif_toggle, execute_process_command, execute_reboot,
    execute_route_add, execute_route_delete, execute_server_apache_action, execute_shutdown,
    execute_software_delete, execute_software_install, file_pdir_download, file_pdir_upload,
    firewall_info_structured, get_server_apache, get_server_install, get_server_noninstall,
    log_info_structured, log_query_structured, netif_info_structured, pdir_info_structured,
    process_info_structured, route_info_structured, software_info_structured, ApacheAccessLogEntry,
    ApacheAction, ApacheDate, ApacheErrorLogEntry, ApacheLogLevel, ApacheLogs, ApacheMonth,
    ApacheServerInfo, ApacheStatus, ApacheWeek, CronJobs, DnsInfo, FirewallStatus, Logs,
    NetworkInterfaces, PackageStatus, ParentDirectory, ProcessAction, ProcessInfo, ReturnStatus,
    RouteTable, ServerHostInfo, ServerStatus, SizeUnit, SoftwareInventory, SystemInfo,
};
use chm_grpc::tonic::{self, Request, Response, Status};
use tokio::sync::Semaphore;

/// Generated gRPC bindings provided by the shared `chm-grpc` crate.
pub mod proto {
    pub use chm_grpc::agent::{
        agent_file_service_server::{AgentFileService, AgentFileServiceServer},
        agent_info_service_server::{AgentInfoService, AgentInfoServiceServer},
        agent_service_server::{AgentService, AgentServiceServer},
        *,
    };
}

/// gRPC service entry point that bridges requests into the existing host
/// communication flow.
#[derive(Clone)]
pub struct AgentGrpcService {
    system: Arc<SystemInfo>,
}

impl AgentGrpcService {
    /// Create a new service wrapper around detected system information.
    pub fn new(system: Arc<SystemInfo>) -> Self {
        Self { system }
    }

    fn system(&self) -> Arc<SystemInfo> {
        Arc::clone(&self.system)
    }
}

trait AgentCommandExt {
    fn as_str(&self) -> &'static str;
}

impl AgentCommandExt for proto::AgentCommand {
    fn as_str(&self) -> &'static str {
        match self {
            proto::AgentCommand::Unspecified => "unspecified",
            proto::AgentCommand::GetProcess => "get_process",
            proto::AgentCommand::GetCron => "get_cron",
            proto::AgentCommand::GetFirewall => "get_firewall",
            proto::AgentCommand::GetNetif => "get_netif",
            proto::AgentCommand::GetRoute => "get_route",
            proto::AgentCommand::GetDns => "get_dns",
            proto::AgentCommand::GetPdir => "get_pdir",
            proto::AgentCommand::GetSoftware => "get_software",
            proto::AgentCommand::GetLog => "get_log",
            proto::AgentCommand::GetLogQuery => "get_log_query",
            proto::AgentCommand::GetServerApache => "get_server_apache",
            proto::AgentCommand::SoftwareInstall => "software_install",
            proto::AgentCommand::SoftwareDelete => "software_delete",
            proto::AgentCommand::ProcessStart => "process_start",
            proto::AgentCommand::ProcessStop => "process_stop",
            proto::AgentCommand::ProcessRestart => "process_restart",
            proto::AgentCommand::ProcessEnable => "process_enable",
            proto::AgentCommand::ProcessDisable => "process_disable",
            proto::AgentCommand::ProcessStartEnable => "process_start_enable",
            proto::AgentCommand::ProcessStopDisable => "process_stop_disable",
            proto::AgentCommand::CronAdd => "cron_add",
            proto::AgentCommand::CronDelete => "cron_delete",
            proto::AgentCommand::CronUpdate => "cron_update",
            proto::AgentCommand::FirewallAdd => "firewall_add",
            proto::AgentCommand::FirewallDelete => "firewall_delete",
            proto::AgentCommand::FirewallEditStatus => "firewall_edit_status",
            proto::AgentCommand::FirewallEditPolicy => "firewall_edit_policy",
            proto::AgentCommand::NetifAdd => "netif_add",
            proto::AgentCommand::NetifDelete => "netif_delete",
            proto::AgentCommand::NetifUp => "netif_up",
            proto::AgentCommand::NetifDown => "netif_down",
            proto::AgentCommand::RouteAdd => "route_add",
            proto::AgentCommand::RouteDelete => "route_delete",
            proto::AgentCommand::Reboot => "reboot",
            proto::AgentCommand::Shutdown => "shutdown",
            proto::AgentCommand::GetInfo => "get_info",
            proto::AgentCommand::ServerApacheStart => "server_apache_start",
            proto::AgentCommand::ServerApacheStop => "server_apache_stop",
            proto::AgentCommand::ServerApacheRestart => "server_apache_restart",
            proto::AgentCommand::GetServerInstall => "get_server_install",
            proto::AgentCommand::GetServerNoninstall => "get_server_noninstall",
        }
    }
}

#[derive(Clone)]
pub struct InfoGrpcService {
    system:      Arc<SystemInfo>,
    concurrency: Arc<Semaphore>,
}

impl InfoGrpcService {
    pub fn new(system: Arc<SystemInfo>, max_concurrent: usize) -> Self {
        let permits = if max_concurrent == 0 { 1 } else { max_concurrent };
        Self { system, concurrency: Arc::new(Semaphore::new(permits)) }
    }

    fn system(&self) -> Arc<SystemInfo> {
        Arc::clone(&self.system)
    }
}

#[tonic::async_trait]
impl proto::AgentService for AgentGrpcService {
    async fn execute_command(
        &self,
        request: Request<proto::CommandRequest>,
    ) -> Result<Response<proto::CommandResponse>, Status> {
        let payload = request.into_inner();
        let command_enum = proto::AgentCommand::try_from(payload.command)
            .map_err(|_| Status::invalid_argument("unknown command value"))?;
        if matches!(command_enum, proto::AgentCommand::Unspecified) {
            return Err(Status::invalid_argument("command cannot be unspecified"));
        }
        if matches!(command_enum, proto::AgentCommand::GetInfo) {
            return Err(Status::unimplemented(
                "get_info is available via AgentInfoService.GetInfo",
            ));
        }
        let argument = payload.argument.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty());
        let command_name = command_enum.as_str();

        match command_enum {
            proto::AgentCommand::GetProcess => {
                let sys = self.system();
                let info =
                    tokio::task::spawn_blocking(move || process_info_structured(sys.as_ref()))
                        .await
                        .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(process_info_to_proto(info)))
            }
            proto::AgentCommand::GetCron => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || cron_info_structured(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(cron_info_to_proto(info)))
            }
            proto::AgentCommand::GetFirewall => {
                let sys = self.system();
                let info =
                    tokio::task::spawn_blocking(move || firewall_info_structured(sys.as_ref()))
                        .await
                        .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(firewall_info_to_proto(info)))
            }
            proto::AgentCommand::GetNetif => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || netif_info_structured(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(netif_info_to_proto(info)))
            }
            proto::AgentCommand::GetRoute => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || route_info_structured(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(route_info_to_proto(info)))
            }
            proto::AgentCommand::GetDns => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || dns_info_structured(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(dns_info_to_proto(info)))
            }
            proto::AgentCommand::GetPdir => {
                let argument_owned = argument.map(|s| s.to_string());
                let info = tokio::task::spawn_blocking(move || {
                    pdir_info_structured(argument_owned.as_deref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(parent_directory_to_proto(info)))
            }
            proto::AgentCommand::GetSoftware => {
                let sys = self.system();
                let info =
                    tokio::task::spawn_blocking(move || software_info_structured(sys.as_ref()))
                        .await
                        .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                        .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(software_inventory_to_proto(info)))
            }
            proto::AgentCommand::GetLog => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || log_info_structured(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(logs_to_proto(info)))
            }
            proto::AgentCommand::GetLogQuery => {
                let argument_owned = argument.map(|s| s.to_string());
                let info = tokio::task::spawn_blocking(move || {
                    log_query_structured(argument_owned.as_deref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(logs_to_proto(info)))
            }
            proto::AgentCommand::GetServerApache => {
                let sys = self.system();
                let info = tokio::task::spawn_blocking(move || get_server_apache(sys.as_ref()))
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?
                    .map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(apache_info_to_proto(info)))
            }
            proto::AgentCommand::ServerApacheStart
            | proto::AgentCommand::ServerApacheStop
            | proto::AgentCommand::ServerApacheRestart => {
                let sys = self.system();
                let action = match command_enum {
                    proto::AgentCommand::ServerApacheStart => ApacheAction::Start,
                    proto::AgentCommand::ServerApacheStop => ApacheAction::Stop,
                    proto::AgentCommand::ServerApacheRestart => ApacheAction::Restart,
                    _ => unreachable!("only apache actions reach this branch"),
                };
                let result = tokio::task::spawn_blocking(move || {
                    execute_server_apache_action(action, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::GetServerInstall => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("get_server_install requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    get_server_install(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(info) => server_host_info_to_proto(info),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::GetServerNoninstall => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("get_server_noninstall requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    get_server_noninstall(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(info) => server_host_info_to_proto(info),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::SoftwareInstall => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("software_install requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_software_install(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::SoftwareDelete => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("software_delete requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_software_delete(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::ProcessStart
            | proto::AgentCommand::ProcessStop
            | proto::AgentCommand::ProcessRestart
            | proto::AgentCommand::ProcessEnable
            | proto::AgentCommand::ProcessDisable
            | proto::AgentCommand::ProcessStartEnable
            | proto::AgentCommand::ProcessStopDisable => {
                let sys = self.system();
                let process_action = match command_enum {
                    proto::AgentCommand::ProcessStart => ProcessAction::Start,
                    proto::AgentCommand::ProcessStop => ProcessAction::Stop,
                    proto::AgentCommand::ProcessRestart => ProcessAction::Restart,
                    proto::AgentCommand::ProcessEnable => ProcessAction::Enable,
                    proto::AgentCommand::ProcessDisable => ProcessAction::Disable,
                    proto::AgentCommand::ProcessStartEnable => ProcessAction::StartEnable,
                    proto::AgentCommand::ProcessStopDisable => ProcessAction::StopDisable,
                    _ => unreachable!("only process actions reach this branch"),
                };
                let argument_owned = argument.map(|s| s.to_string());
                let result = tokio::task::spawn_blocking(move || {
                    execute_process_command(process_action, argument_owned.as_deref(), sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;

                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::CronAdd => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("cron_add requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_cron_add(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::CronDelete => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("cron_delete requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_cron_delete(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::CronUpdate => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("cron_update requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_cron_update(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::FirewallAdd => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("firewall_add requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_firewall_add(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::FirewallDelete => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("firewall_delete requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_firewall_delete(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::FirewallEditStatus => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("firewall_edit_status requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_firewall_edit_status(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::FirewallEditPolicy => {
                let argument = argument.ok_or_else(|| {
                    Status::invalid_argument("firewall_edit_policy requires an argument")
                })?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_firewall_edit_policy(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::NetifAdd => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("netif_add requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_netif_add(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::NetifDelete => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("netif_delete requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_netif_delete(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::NetifUp => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("netif_up requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_netif_toggle(&argument_owned, sys.as_ref(), true)
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::NetifDown => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("netif_down requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_netif_toggle(&argument_owned, sys.as_ref(), false)
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::RouteAdd => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("route_add requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_route_add(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::RouteDelete => {
                let argument = argument
                    .ok_or_else(|| Status::invalid_argument("route_delete requires an argument"))?;
                let argument_owned = argument.to_string();
                let sys = self.system();
                let result = tokio::task::spawn_blocking(move || {
                    execute_route_delete(&argument_owned, sys.as_ref())
                })
                .await
                .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                let response = match result {
                    Ok(message) => build_return_info(ReturnStatus::Ok, message),
                    Err(err) => build_return_info(ReturnStatus::Err, err),
                };
                Ok(Response::new(response))
            }
            proto::AgentCommand::Reboot => {
                let info = tokio::task::spawn_blocking(execute_reboot)
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                Ok(Response::new(return_info_to_proto(info)))
            }
            proto::AgentCommand::Shutdown => {
                let info = tokio::task::spawn_blocking(execute_shutdown)
                    .await
                    .map_err(|e| Status::internal(format!("task join error: {}", e)))?;
                Ok(Response::new(return_info_to_proto(info)))
            }
            _ => Err(Status::unimplemented(format!("unsupported command: {}", command_name))),
        }
    }
}

#[tonic::async_trait]
impl proto::AgentInfoService for InfoGrpcService {
    async fn get_info(
        &self,
        _request: Request<proto::GetInfoRequest>,
    ) -> Result<Response<proto::AgentInfo>, Status> {
        let permit = self
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("too many concurrent get_info requests"))?;

        let sys = self.system();
        let info = tokio::task::spawn_blocking(move || agent_info_structured(sys.as_ref()))
            .await
            .map_err(|e| Status::internal(format!("task join error: {}", e)))?
            .map_err(|e| Status::internal(e.to_string()))?;
        drop(permit);

        Ok(Response::new(proto::AgentInfo { cpu: info.cpu, mem: info.mem, disk: info.disk }))
    }
}

#[derive(Clone)]
pub struct FileGrpcService {
    concurrency: Arc<Semaphore>,
}

impl FileGrpcService {
    pub fn new(max_concurrent: usize) -> Self {
        let permits = if max_concurrent == 0 { 1 } else { max_concurrent };
        Self { concurrency: Arc::new(Semaphore::new(permits)) }
    }
}

#[tonic::async_trait]
impl proto::AgentFileService for FileGrpcService {
    async fn file_pdir_upload(
        &self,
        request: Request<proto::FileUploadRequest>,
    ) -> Result<Response<proto::ReturnInfo>, Status> {
        let _permit = self
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::internal("file upload concurrency limiter closed"))?;

        let payload = request.into_inner();
        let path = payload.path.trim();
        if path.is_empty() {
            return Err(Status::invalid_argument("Path cannot be empty"));
        }
        let file_content = payload.file.trim();
        if file_content.is_empty() {
            return Err(Status::invalid_argument("File content cannot be empty"));
        }

        let response = match file_pdir_upload(path, file_content) {
            Ok(()) => proto::ReturnInfo {
                r#type:  "OK".to_string(),
                message: "upload success".to_string(),
            },
            Err(err) => proto::ReturnInfo { r#type: "ERR".to_string(), message: err },
        };

        Ok(Response::new(response))
    }

    async fn file_pdir_download(
        &self,
        request: Request<proto::FileDownloadRequest>,
    ) -> Result<Response<proto::FileDownloadResponse>, Status> {
        let _permit = self
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::internal("file download concurrency limiter closed"))?;

        let payload = request.into_inner();
        let path = payload.path.trim();
        let filename = payload.filename.trim();
        if path.is_empty() || filename.is_empty() {
            return Err(Status::invalid_argument("Path and Filename cannot be empty"));
        }

        let result = match file_pdir_download(path, filename) {
            Ok(content) => proto::file_download_response::Result::File(content),
            Err(err) => proto::file_download_response::Result::ReturnInfo(proto::ReturnInfo {
                r#type:  "ERR".to_string(),
                message: err,
            }),
        };

        Ok(Response::new(proto::FileDownloadResponse { result: Some(result) }))
    }
}

fn process_info_to_proto(info: ProcessInfo) -> proto::CommandResponse {
    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ProcessInfo(proto::ProcessInfo {
            entries: info
                .entries
                .into_iter()
                .map(|entry| proto::ProcessEntry {
                    name:   entry.name,
                    status: Some(proto::ProcessStatus {
                        status: entry.status.status,
                        boot:   entry.status.boot,
                    }),
                })
                .collect(),
            length:  info.length as u32,
        })),
    }
}

fn firewall_info_to_proto(info: FirewallStatus) -> proto::CommandResponse {
    let chains: Vec<proto::FirewallChain> = info
        .chains
        .into_iter()
        .map(|chain| {
            let rules: Vec<proto::FirewallRule> = chain
                .rules
                .into_iter()
                .map(|rule| proto::FirewallRule {
                    id:          rule.id,
                    target:      rule.target.as_str().to_string(),
                    protocol:    rule.protocol,
                    r#in:        rule.in_interface,
                    out:         rule.out_interface,
                    source:      rule.source,
                    destination: rule.destination,
                    options:     rule.options,
                })
                .collect();

            proto::FirewallChain {
                name: chain.name,
                policy: chain.policy.as_str().to_string(),
                rules,
                rules_length: chain.rules_length as u32,
            }
        })
        .collect();

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::FirewallStatus(proto::FirewallStatus {
            status: info.status.as_str().to_string(),
            chains,
        })),
    }
}

fn build_return_info(status: ReturnStatus, message: impl Into<String>) -> proto::CommandResponse {
    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ReturnInfo(proto::ReturnInfo {
            r#type:  status.as_str().to_string(),
            message: message.into(),
        })),
    }
}

fn return_info_to_proto(info: crate::ReturnInfo) -> proto::CommandResponse {
    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ReturnInfo(proto::ReturnInfo {
            r#type:  info.status.as_str().to_string(),
            message: info.message,
        })),
    }
}

fn netif_info_to_proto(info: NetworkInterfaces) -> proto::CommandResponse {
    let interfaces: Vec<proto::NetworkInterface> = info
        .networks
        .into_iter()
        .map(|iface| proto::NetworkInterface {
            id:        iface.id,
            r#type:    iface.iface_type.as_str().to_string(),
            ipv4:      iface.ipv4,
            netmask:   iface.netmask,
            mac:       iface.mac,
            broadcast: iface.broadcast,
            mtu:       iface.mtu,
            status:    iface.status.as_str().to_string(),
        })
        .collect();

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::NetworkInterfaces(
            proto::NetworkInterfaces { interfaces, length: info.length as u32 },
        )),
    }
}

fn route_info_to_proto(info: RouteTable) -> proto::CommandResponse {
    let mut routes_map = std::collections::HashMap::new();
    for route in info.routes {
        routes_map.insert(
            route.destination.clone(),
            proto::RouteEntry {
                destination: route.destination,
                via:         route.via,
                dev:         route.dev,
                proto:       route.proto,
                metric:      route.metric,
                scope:       route.scope,
                src:         route.src,
            },
        );
    }

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::RouteTable(proto::RouteTable {
            routes: routes_map,
            length: info.length as u32,
        })),
    }
}

fn dns_info_to_proto(info: DnsInfo) -> proto::CommandResponse {
    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::DnsInfo(proto::DnsInfo {
            hostname:  info.hostname,
            primary:   info.primary,
            secondary: info.secondary,
        })),
    }
}

fn parent_directory_to_proto(info: ParentDirectory) -> proto::CommandResponse {
    let mut files = std::collections::HashMap::new();
    for (name, entry) in info.files {
        files.insert(
            name,
            proto::DirectoryEntry {
                size:     entry.size,
                unit:     size_unit_to_proto(entry.unit),
                owner:    entry.owner,
                mode:     entry.mode,
                modified: entry.modified,
            },
        );
    }

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ParentDirectory(proto::ParentDirectory {
            files,
            length: info.length as u32,
        })),
    }
}

fn size_unit_to_proto(unit: SizeUnit) -> i32 {
    match unit {
        SizeUnit::B => proto::DirectorySizeUnit::B as i32,
        SizeUnit::KB => proto::DirectorySizeUnit::Kb as i32,
        SizeUnit::MB => proto::DirectorySizeUnit::Mb as i32,
        SizeUnit::GB => proto::DirectorySizeUnit::Gb as i32,
    }
}

fn software_inventory_to_proto(info: SoftwareInventory) -> proto::CommandResponse {
    let mut packages = std::collections::HashMap::new();
    for (name, package) in info.packages {
        packages.insert(
            name,
            proto::SoftwarePackage {
                version: package.version,
                status:  package_status_to_proto(package.status),
            },
        );
    }

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::SoftwareInventory(
            proto::SoftwareInventory { packages },
        )),
    }
}

fn logs_to_proto(info: Logs) -> proto::CommandResponse {
    let mut logs_map = std::collections::HashMap::new();
    for (id, entry) in info.entries {
        logs_map.insert(
            id,
            proto::LogEntry {
                month:    entry.month,
                day:      entry.day,
                time:     entry.time,
                hostname: entry.hostname,
                r#type:   entry.r#type,
                messages: entry.messages,
            },
        );
    }

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::Logs(proto::Logs {
            logs:   logs_map,
            length: info.length as u32,
        })),
    }
}

fn server_host_info_to_proto(info: ServerHostInfo) -> proto::CommandResponse {
    let status = match info.status {
        ServerStatus::Active => proto::server_host_info::Status::Active as i32,
        ServerStatus::Stopped => proto::server_host_info::Status::Stopped as i32,
    };

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ServerHostInfo(proto::ServerHostInfo {
            hostname: info.hostname,
            status,
            cpu: info.cpu,
            memory: info.memory,
            ip: info.ip,
        })),
    }
}

fn apache_info_to_proto(info: ApacheServerInfo) -> proto::CommandResponse {
    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::ApacheInfo(proto::ApacheInfo {
            hostname:    info.hostname,
            status:      apache_status_to_proto(info.status),
            cpu:         info.cpu,
            memory:      info.memory,
            connections: info.connections,
            ip:          info.ip,
            logs:        Some(apache_logs_to_proto(info.logs)),
        })),
    }
}

fn apache_logs_to_proto(logs: ApacheLogs) -> proto::ApacheLogs {
    let error_log = logs.error_log.into_iter().map(apache_error_log_to_proto).collect();
    let access_log = logs.access_log.into_iter().map(apache_access_log_to_proto).collect();
    proto::ApacheLogs {
        error_log,
        errlength: usize_to_u64(logs.errlength),
        access_log,
        acclength: usize_to_u64(logs.acclength),
    }
}

fn apache_error_log_to_proto(entry: ApacheErrorLogEntry) -> proto::ApacheErrorLog {
    proto::ApacheErrorLog {
        date:    Some(apache_date_to_proto(entry.date)),
        module:  entry.module,
        level:   apache_log_level_to_proto(entry.level),
        pid:     if entry.pid < 0 { 0 } else { entry.pid as u64 },
        client:  entry.client,
        message: entry.message,
    }
}

fn apache_access_log_to_proto(entry: ApacheAccessLogEntry) -> proto::ApacheAccessLog {
    proto::ApacheAccessLog {
        ip:         entry.ip,
        date:       Some(apache_date_to_proto(entry.date)),
        method:     entry.method,
        url:        entry.url,
        protocol:   entry.protocol,
        status:     entry.status,
        byte:       entry.byte,
        referer:    entry.referer,
        user_agent: entry.user_agent,
    }
}

fn apache_date_to_proto(date: ApacheDate) -> proto::ApacheDate {
    proto::ApacheDate {
        year:  date.year,
        month: apache_month_to_proto(date.month),
        day:   date.day,
        week:  apache_week_to_proto(date.week),
        time:  Some(proto::apache_date::Time { hour: date.time.hour, min: date.time.min }),
    }
}

fn apache_status_to_proto(status: ApacheStatus) -> i32 {
    match status {
        ApacheStatus::Active => proto::ApacheStatus::Active as i32,
        ApacheStatus::Stopped => proto::ApacheStatus::Stopped as i32,
        ApacheStatus::Uninstalled => proto::ApacheStatus::Uninstalled as i32,
    }
}

fn apache_log_level_to_proto(level: ApacheLogLevel) -> i32 {
    match level {
        ApacheLogLevel::Debug => proto::ApacheLogLevel::Debug as i32,
        ApacheLogLevel::Info => proto::ApacheLogLevel::Info as i32,
        ApacheLogLevel::Notice => proto::ApacheLogLevel::Notice as i32,
        ApacheLogLevel::Warn => proto::ApacheLogLevel::Warn as i32,
        ApacheLogLevel::Error => proto::ApacheLogLevel::Error as i32,
        ApacheLogLevel::Crit => proto::ApacheLogLevel::Crit as i32,
        ApacheLogLevel::Alert => proto::ApacheLogLevel::Alert as i32,
        ApacheLogLevel::Emerg => proto::ApacheLogLevel::Emerg as i32,
    }
}

fn apache_week_to_proto(week: ApacheWeek) -> i32 {
    match week {
        ApacheWeek::Mon => proto::ApacheWeek::Mon as i32,
        ApacheWeek::Tue => proto::ApacheWeek::Tue as i32,
        ApacheWeek::Wed => proto::ApacheWeek::Wed as i32,
        ApacheWeek::Thu => proto::ApacheWeek::Thu as i32,
        ApacheWeek::Fri => proto::ApacheWeek::Fri as i32,
        ApacheWeek::Sat => proto::ApacheWeek::Sat as i32,
        ApacheWeek::Sun => proto::ApacheWeek::Sun as i32,
    }
}

fn apache_month_to_proto(month: ApacheMonth) -> i32 {
    match month {
        ApacheMonth::Jan => proto::ApacheMonth::Jan as i32,
        ApacheMonth::Feb => proto::ApacheMonth::Feb as i32,
        ApacheMonth::Mar => proto::ApacheMonth::Mar as i32,
        ApacheMonth::Apr => proto::ApacheMonth::Apr as i32,
        ApacheMonth::May => proto::ApacheMonth::May as i32,
        ApacheMonth::Jun => proto::ApacheMonth::Jun as i32,
        ApacheMonth::Jul => proto::ApacheMonth::Jul as i32,
        ApacheMonth::Aug => proto::ApacheMonth::Aug as i32,
        ApacheMonth::Sep => proto::ApacheMonth::Sep as i32,
        ApacheMonth::Oct => proto::ApacheMonth::Oct as i32,
        ApacheMonth::Nov => proto::ApacheMonth::Nov as i32,
        ApacheMonth::Dec => proto::ApacheMonth::Dec as i32,
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn package_status_to_proto(status: PackageStatus) -> i32 {
    match status {
        PackageStatus::Installed => proto::PackageStatus::Installed as i32,
        PackageStatus::Notinstall => proto::PackageStatus::Notinstall as i32,
    }
}

fn cron_info_to_proto(info: CronJobs) -> proto::CommandResponse {
    let mut jobs: Vec<proto::CronJob> = info
        .jobs
        .into_iter()
        .map(|job| proto::CronJob {
            id:       job.id,
            name:     job.name,
            command:  job.command,
            schedule: Some(proto::CronSchedule {
                minute: job.schedule.minute,
                hour:   job.schedule.hour,
                date:   job.schedule.date,
                month:  job.schedule.month,
                week:   job.schedule.week,
            }),
            username: job.username,
        })
        .collect();
    // Provide deterministic ordering for clients.
    jobs.sort_by(|a, b| a.id.cmp(&b.id));
    let length = info.length as u32;

    proto::CommandResponse {
        payload: Some(proto::command_response::Payload::CronJobs(proto::CronJobs { jobs, length })),
    }
}
