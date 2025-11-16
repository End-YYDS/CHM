#![allow(dead_code)]
use crate::{ConResult, GlobalConfig};
use backoff::ExponentialBackoff;
use chm_cluster_utils::{
    gclient::{grpc_connect_with_retry, GrpcConnectOptions},
    ServiceDescriptor, ServiceKind,
};
use chm_dns_resolver::DnsResolver;
use chm_grpc::{
    tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity},
    tonic_health::pb::{health_client::HealthClient, HealthCheckRequest},
};
use futures::{stream, StreamExt};
use rand::{rng, seq::SliceRandom};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

use rustc_hash::FxHashMap as FastMap;
use smallvec::SmallVec;

pub(crate) mod agent;
pub(crate) mod ca;
pub(crate) mod dhcp;
pub(crate) mod dns;
pub(crate) mod ldap;

pub type PairMap = HashMap<ServiceKind, Vec<(ServiceDescriptor, Channel)>>;
pub type ClientMap = HashMap<ServiceKind, Vec<ClientHandle>>;

#[derive(Debug, Clone)]
pub enum PickStrategy {
    RoundRobin,
    Random { attempts: usize },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ClientHandle {
    Ca(ca::ClientCA),
    Dns(dns::ClientDNS),
    Ldap(ldap::ClientLdap),
    Dhcp(dhcp::ClientDhcp),
    Agent(agent::ClientAgent),
}

pub struct ClientFactories {
    pub ca:    fn(Channel) -> ca::ClientCA,
    pub dns:   fn(Channel) -> dns::ClientDNS,
    pub ldap:  fn(Channel) -> ldap::ClientLdap,
    pub dhcp:  fn(Channel) -> dhcp::ClientDhcp,
    pub agent: fn(Channel, chm_project_const::uuid::Uuid, String) -> agent::ClientAgent,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct GrpcClients {
    pub map:           ClientMap,
    rr:                FastMap<ServiceKind, Arc<AtomicUsize>>,
    health:            FastMap<ServiceKind, Vec<Arc<AtomicBool>>>,
    agent_by_uuid:     FastMap<String, SmallVec<[usize; 1]>>,
    agent_by_hostname: FastMap<String, SmallVec<[usize; 1]>>,
    unhealthy_until:   FastMap<ServiceKind, Vec<Arc<AtomicU64>>>,
    quarantine_ms:     u64,
}

impl GrpcClients {
    pub async fn connect_all(only_ca: bool) -> ConResult<Self> {
        init_channels_all(only_ca).await
    }
    pub fn with_map(map: ClientMap) -> Self {
        let quarantine_ms = GlobalConfig::with(|cfg| cfg.extend.quarantine.as_millis() as u64);
        let rr = map.keys().map(|&k| (k, Arc::new(AtomicUsize::new(0)))).collect();

        let mut health: FastMap<ServiceKind, Vec<Arc<AtomicBool>>> = FastMap::default();
        let mut unhealthy_until: FastMap<ServiceKind, Vec<Arc<AtomicU64>>> = FastMap::default();

        for (&k, v) in &map {
            let ok_flags = v.iter().map(|_| Arc::new(AtomicBool::new(true))).collect();
            let ttls = v.iter().map(|_| Arc::new(AtomicU64::new(0))).collect();
            health.insert(k, ok_flags);
            unhealthy_until.insert(k, ttls);
        }

        let mut agent_by_uuid: FastMap<String, SmallVec<[usize; 1]>> = FastMap::default();
        let mut agent_by_hostname: FastMap<String, SmallVec<[usize; 1]>> = FastMap::default();

        if let Some(list) = map.get(&ServiceKind::Agent) {
            for (idx, h) in list.iter().enumerate() {
                if let ClientHandle::Agent(agent) = h {
                    agent_by_uuid.entry(agent.uuid().to_string()).or_default().push(idx);
                    agent_by_hostname.entry(agent.hostname().to_string()).or_default().push(idx);
                }
            }
        }

        Self { map, rr, health, agent_by_uuid, agent_by_hostname, unhealthy_until, quarantine_ms }
    }

    #[inline]
    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    #[inline]
    pub fn set_quarantine_ms(&mut self, ms: u64) {
        self.quarantine_ms = ms;
    }

    #[inline]
    pub fn mark_healthy(&self, kind: ServiceKind, idx: usize, healthy: bool) {
        // if let Some(v) = self.health.get(&kind).and_then(|v| v.get(idx)) {
        //     v.store(healthy, Ordering::Relaxed);
        // }
        // if healthy {
        //     if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v| v.get(idx))
        // {         v.store(0, Ordering::Relaxed);
        //     }
        // } else if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v|
        // v.get(idx)) {     v.store(Self::now_ms() + self.quarantine_ms,
        // Ordering::Relaxed); }
        if healthy {
            if let Some(v) = self.health.get(&kind).and_then(|v| v.get(idx)) {
                v.store(true, Ordering::Relaxed);
            }
            if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v| v.get(idx)) {
                v.store(0, Ordering::Relaxed);
            }
        } else if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v| v.get(idx)) {
            v.store(Self::now_ms() + self.quarantine_ms, Ordering::Relaxed);
        }
    }
    #[inline]
    pub fn set_all_healthy(&self, kind: ServiceKind) {
        if let Some(v) = self.health.get(&kind) {
            for flag in v {
                flag.store(true, Ordering::Relaxed);
            }
        }
        if let Some(v) = self.unhealthy_until.get(&kind) {
            for t in v {
                t.store(0, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn is_healthy(&self, kind: ServiceKind, idx: usize) -> bool {
        self.health
            .get(&kind)
            .and_then(|v| v.get(idx))
            .map(|f| f.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
    #[inline]
    fn is_eligible(&self, kind: ServiceKind, idx: usize) -> bool {
        // if !self.is_healthy(kind, idx) {
        //     return false;
        // }
        // if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v| v.get(idx)) {
        //     let until = v.load(Ordering::Relaxed);
        //     return until <= Self::now_ms();
        // }
        // true
        if !self.is_healthy(kind, idx) {
            return false;
        }
        if let Some(v) = self.unhealthy_until.get(&kind).and_then(|v| v.get(idx)) {
            let until = v.load(Ordering::Relaxed);
            if until == 0 {
                return true;
            }
            return until <= Self::now_ms();
        }
        true
    }
    #[inline]
    fn handle_to_channel(handle: &ClientHandle) -> Channel {
        match handle {
            ClientHandle::Ca(c) => c.channel(),
            ClientHandle::Dns(c) => c.channel(),
            ClientHandle::Ldap(c) => c.channel(),
            ClientHandle::Dhcp(c) => c.channel(),
            ClientHandle::Agent(c) => c.channel(),
        }
    }
    pub fn round_robin(&self, kind: ServiceKind) -> Option<(usize, &ClientHandle)> {
        let list = self.map.get(&kind)?;
        if list.is_empty() {
            return None;
        }
        let start = self.rr.get(&kind)?.fetch_add(1, Ordering::Relaxed) % list.len();
        for offset in 0..list.len() {
            let idx = (start + offset) % list.len();
            if self.is_eligible(kind, idx) {
                return Some((idx, &list[idx]));
            }
        }
        None
    }
    pub fn random_with_retry(
        &self,
        kind: ServiceKind,
        attempts: usize,
    ) -> Option<(usize, &ClientHandle)> {
        let list = self.map.get(&kind)?;
        if list.is_empty() {
            return None;
        }
        let mut idxs: Vec<usize> = (0..list.len()).collect();
        idxs.shuffle(&mut rng());
        for idx in idxs.into_iter().take(attempts.max(1)) {
            if self.is_eligible(kind, idx) {
                return Some((idx, &list[idx]));
            }
        }
        None
    }
    pub fn pick_channel(
        &self,
        kind: ServiceKind,
        strategy: PickStrategy,
    ) -> Option<(usize, Channel)> {
        match strategy {
            PickStrategy::RoundRobin => {
                let (idx, h) = self.round_robin(kind)?;
                Some((idx, Self::handle_to_channel(h)))
            }
            PickStrategy::Random { attempts } => {
                let (idx, h) = self.random_with_retry(kind, attempts)?;
                Some((idx, Self::handle_to_channel(h)))
            }
        }
    }
    pub fn pick_channel_only(&self, kind: ServiceKind, strategy: PickStrategy) -> Option<Channel> {
        self.pick_channel(kind, strategy).map(|(_, ch)| ch)
    }
    pub fn first_client(&self, kind: ServiceKind) -> Option<&ClientHandle> {
        self.map.get(&kind).and_then(|v| v.first())
    }
    pub fn all_channels(&self, kind: ServiceKind) -> Vec<Channel> {
        self.map
            .get(&kind)
            .map(|v| v.iter().map(Self::handle_to_channel).collect())
            .unwrap_or_default()
    }
    fn pick_typed<T, F>(
        &self,
        kind: ServiceKind,
        strat: PickStrategy,
        cast: F,
    ) -> Option<(usize, T)>
    where
        F: Fn(&ClientHandle) -> Option<T>,
        T: Clone,
    {
        match strat {
            PickStrategy::RoundRobin => {
                let (start_idx, _) = self.round_robin(kind)?;
                let list = self.map.get(&kind)?;
                for off in 0..list.len() {
                    let idx = (start_idx + off) % list.len();
                    if self.is_eligible(kind, idx) {
                        if let Some(v) = cast(&list[idx]) {
                            return Some((idx, v.clone()));
                        }
                    }
                }
                None
            }
            PickStrategy::Random { attempts } => {
                let list = self.map.get(&kind)?;
                if list.is_empty() {
                    return None;
                }
                let mut idxs: Vec<usize> = (0..list.len()).collect();
                idxs.shuffle(&mut rng());
                for idx in idxs.into_iter().take(attempts.max(1)) {
                    if self.is_eligible(kind, idx) {
                        if let Some(v) = cast(&list[idx]) {
                            return Some((idx, v.clone()));
                        }
                    }
                }
                None
            }
        }
    }

    #[inline]
    fn ca_handle_with_idx(&self) -> Option<(usize, ca::ClientCA)> {
        self.pick_typed(ServiceKind::Mca, PickStrategy::RoundRobin, |h| match h {
            ClientHandle::Ca(c) => Some(c.clone()),
            _ => None,
        })
    }

    #[inline]
    fn dns_handle_with_idx(&self) -> Option<(usize, dns::ClientDNS)> {
        self.pick_typed(ServiceKind::Dns, PickStrategy::RoundRobin, |h| match h {
            ClientHandle::Dns(c) => Some(c.clone()),
            _ => None,
        })
    }

    #[inline]
    fn ldap_handle_with_idx(&self) -> Option<(usize, ldap::ClientLdap)> {
        self.pick_typed(ServiceKind::Ldap, PickStrategy::RoundRobin, |h| match h {
            ClientHandle::Ldap(c) => Some(c.clone()),
            _ => None,
        })
    }

    #[inline]
    fn dhcp_handle_with_idx(&self) -> Option<(usize, dhcp::ClientDhcp)> {
        self.pick_typed(ServiceKind::Dhcp, PickStrategy::RoundRobin, |h| match h {
            ClientHandle::Dhcp(c) => Some(c.clone()),
            _ => None,
        })
    }

    /// Agent by uuid/hostname：遍歷候選列表，回退到第一個健康實例
    pub fn pick_agent_by_uuid(&self, uuid: &str) -> Option<(usize, &agent::ClientAgent)> {
        let list = self.map.get(&ServiceKind::Agent)?;
        let candidates = self.agent_by_uuid.get(uuid)?;
        for &idx in candidates {
            if let Some(ClientHandle::Agent(a)) = list.get(idx) {
                if self.is_eligible(ServiceKind::Agent, idx) {
                    return Some((idx, a));
                }
            }
        }
        None
    }

    pub fn pick_agent_by_hostname(&self, hostname: &str) -> Option<(usize, &agent::ClientAgent)> {
        let list = self.map.get(&ServiceKind::Agent)?;
        let candidates = self.agent_by_hostname.get(hostname)?;
        for &idx in candidates {
            if let Some(ClientHandle::Agent(a)) = list.get(idx) {
                if self.is_eligible(ServiceKind::Agent, idx) {
                    return Some((idx, a));
                }
            }
        }
        None
    }

    pub fn pick_agent_channel_by_uuid(&self, uuid: &str) -> Option<(usize, Channel)> {
        let (idx, a) = self.pick_agent_by_uuid(uuid)?;
        Some((idx, a.channel()))
    }

    pub fn pick_agent_channel_by_hostname(&self, hostname: &str) -> Option<(usize, Channel)> {
        let (idx, a) = self.pick_agent_by_hostname(hostname)?;
        Some((idx, a.channel()))
    }

    pub fn ca_handle(&self) -> Option<ca::ClientCA> {
        self.ca_handle_with_idx().map(|(_, h)| h)
    }
    pub fn dns_handle(&self) -> Option<dns::ClientDNS> {
        self.dns_handle_with_idx().map(|(_, h)| h)
    }
    pub fn ldap_handle(&self) -> Option<ldap::ClientLdap> {
        self.ldap_handle_with_idx().map(|(_, h)| h)
    }
    pub fn dhcp_handle(&self) -> Option<dhcp::ClientDhcp> {
        self.dhcp_handle_with_idx().map(|(_, h)| h)
    }

    #[inline]
    pub fn try_ca(&self) -> ConResult<ca::ClientCA> {
        self.ca_handle().ok_or_else(|| "沒有可用的 CA 節點".into())
    }
    #[inline]
    pub fn try_dns(&self) -> ConResult<dns::ClientDNS> {
        self.dns_handle().ok_or_else(|| "沒有可用的 DNS 節點".into())
    }
    #[inline]
    pub fn try_ldap(&self) -> ConResult<ldap::ClientLdap> {
        self.ldap_handle().ok_or_else(|| "沒有可用的 LDAP 節點".into())
    }
    #[inline]
    pub fn try_dhcp(&self) -> ConResult<dhcp::ClientDhcp> {
        self.dhcp_handle().ok_or_else(|| "沒有可用的 DHCP 節點".into())
    }

    pub async fn with_ca_handle<F, Fut, T>(&self, f: F) -> ConResult<T>
    where
        F: FnOnce(ca::ClientCA) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self.ca_handle_with_idx().ok_or("沒有可用的 CA 節點")?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Mca, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Mca, idx, false);
        }
        out
    }

    pub async fn with_dns_handle<F, Fut, T>(&self, f: F) -> ConResult<T>
    where
        F: FnOnce(dns::ClientDNS) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self.dns_handle_with_idx().ok_or("沒有可用的 DNS 節點")?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Dns, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Dns, idx, false);
        }
        out
    }

    pub async fn with_ldap_handle<F, Fut, T>(&self, f: F) -> ConResult<T>
    where
        F: FnOnce(ldap::ClientLdap) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self.ldap_handle_with_idx().ok_or("沒有可用的 LDAP 節點")?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Ldap, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Ldap, idx, false);
        }
        out
    }

    pub async fn with_dhcp_handle<F, Fut, T>(&self, f: F) -> ConResult<T>
    where
        F: FnOnce(dhcp::ClientDhcp) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self.dhcp_handle_with_idx().ok_or("沒有可用的 DHCP 節點")?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Dhcp, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Dhcp, idx, false);
        }
        out
    }

    pub async fn with_agent_uuid_handle<F, Fut, T>(&self, uuid: &str, f: F) -> ConResult<T>
    where
        F: FnOnce(agent::ClientAgent) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self
            .agent_handle_by_uuid_with_idx(uuid)
            .ok_or_else(|| format!("指定 uuid={} 的 Agent 不可用", uuid))?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Agent, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Agent, idx, false);
        }
        out
    }

    pub async fn with_agent_host_handle<F, Fut, T>(&self, hostname: &str, f: F) -> ConResult<T>
    where
        F: FnOnce(agent::ClientAgent) -> Fut,
        Fut: std::future::Future<Output = ConResult<T>>,
    {
        let (idx, h) = self
            .agent_handle_by_hostname_with_idx(hostname)
            .ok_or_else(|| format!("指定 hostname={} 的 Agent 不可用", hostname))?;
        let out = f(h).await;
        if out.is_ok() {
            self.mark_healthy(ServiceKind::Agent, idx, true);
        } else {
            self.mark_healthy(ServiceKind::Agent, idx, false);
        }
        out
    }

    #[inline]
    fn agent_handle_by_uuid_with_idx(&self, uuid: &str) -> Option<(usize, agent::ClientAgent)> {
        let list = self.map.get(&ServiceKind::Agent)?;
        let candidates = self.agent_by_uuid.get(uuid)?;
        for &idx in candidates {
            if let Some(ClientHandle::Agent(a)) = list.get(idx) {
                if self.is_eligible(ServiceKind::Agent, idx) {
                    return Some((idx, a.clone()));
                }
            }
        }
        None
    }

    #[inline]
    fn agent_handle_by_hostname_with_idx(
        &self,
        hostname: &str,
    ) -> Option<(usize, agent::ClientAgent)> {
        let list = self.map.get(&ServiceKind::Agent)?;
        let candidates = self.agent_by_hostname.get(hostname)?;
        for &idx in candidates {
            if let Some(ClientHandle::Agent(a)) = list.get(idx) {
                if self.is_eligible(ServiceKind::Agent, idx) {
                    return Some((idx, a.clone()));
                }
            }
        }
        None
    }
}

pub async fn health_check(channel: Channel, service_name: impl AsRef<str>) -> ConResult<()> {
    let svc = service_name.as_ref();
    tracing::debug!("執行 {svc} 健康檢查...");
    let mut health = HealthClient::new(channel.clone());
    let resp = health.check(HealthCheckRequest { service: svc.into() }).await?.into_inner();
    tracing::debug!("{svc} 健康狀態 = {:?}", resp.status());
    Ok(())
}
pub async fn connect_all_services(
    only_ca: bool,
    services: &[ServiceDescriptor],
    tls: ClientTlsConfig,
    backoff: ExponentialBackoff,
    opts: &GrpcConnectOptions,
) -> ConResult<HashMap<ServiceKind, Vec<(ServiceDescriptor, Channel)>>> {
    let selected: Vec<ServiceDescriptor> = if only_ca {
        let ca_services: Vec<ServiceDescriptor> =
            services.iter().filter(|s| s.kind == ServiceKind::Mca).cloned().collect();
        if ca_services.is_empty() {
            return Err("配置中沒有找到 CA 服務".into());
        }
        ca_services
    } else {
        services.to_vec()
    };
    let dns_resolver = if only_ca {
        None
    } else {
        let mut mdns_addr = GlobalConfig::with(|cfg| cfg.server.dns_server.clone());
        let default_port = GlobalConfig::with(|cfg| cfg.server.port);
        let ip_port = Url::parse(&mdns_addr).expect("必須為正常Url");
        if ip_port.port().is_none() {
            let scheme = ip_port.scheme();
            let new_host = if scheme != "https" {
                panic!("僅支援 https:// 開頭的網址");
            } else {
                ip_port.host_str().expect("無法解析主機名稱").to_string()
            };
            mdns_addr = format!("{scheme}://{new_host}:{default_port}");
            tracing::warn!(
                "目標DNS網址未指定 Port，已自動補上預設 Port 11209，新的目標網址為: {mdns_addr}"
            );
        }
        Some(Arc::new(DnsResolver::new(mdns_addr, tls.clone()).await))
    };
    let concurrency = GlobalConfig::with(|cfg| cfg.extend.concurrency);
    let results = stream::iter(selected.into_iter().map(|svc| {
        let tls = tls.clone();
        let opts = opts.clone();
        let backoff = backoff.clone();
        let dns_resolver = dns_resolver.clone();

        async move {
            let ch = grpc_connect_with_retry(
                &svc.uri,
                tls,
                backoff,
                &opts,
                &svc.hostname,
                dns_resolver.clone(),
                None,
                svc.health_name.as_deref(),
            )
            .await?;

            if let Some(health_name) = svc.health_name.as_deref() {
                health_check(ch.clone(), health_name).await?;
            } else {
                tracing::info!("{} 跳過健康檢查", svc.hostname);
            }

            ConResult::<(ServiceKind, (ServiceDescriptor, Channel))>::Ok((svc.kind, (svc, ch)))
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;
    // TODO: 限制同時連線數量
    // TODO: 全部失敗才回Err
    // TODO: 同一個服務多個實例時的處理
    // let pairs: Vec<(ServiceKind, Channel)> = try_join_all(futs).await?;
    let mut ok_map: HashMap<ServiceKind, Vec<(ServiceDescriptor, Channel)>> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();
    for res in results {
        match res {
            Ok((kind, pair)) => {
                ok_map.entry(kind).or_default().push(pair);
            }
            Err(e) => {
                errors.push(e.to_string());
            }
        }
    }
    if ok_map.is_empty() {
        let msg = if errors.is_empty() {
            "所有服務連線皆失敗".to_string()
        } else {
            format!(
                "所有服務連線皆失敗；錯誤 {} 筆，部分例子：{}",
                errors.len(),
                errors.iter().take(3).cloned().collect::<Vec<_>>().join(" | ")
            )
        };
        return Err(msg.into());
    }

    if !errors.is_empty() {
        tracing::error!("部分服務連線失敗（{} 筆），其餘已成功建立", errors.len());
    }
    Ok(ok_map)
}

pub async fn init_channels_all(only_ca: bool) -> ConResult<GrpcClients> {
    let (root, cert, key) = GlobalConfig::with(|cfg| -> ConResult<_> {
        let root = cfg.certificate.root_ca.clone();
        let cert = cfg.certificate.client_cert.clone();
        let key = cfg.certificate.client_key.clone();
        if root.as_os_str().is_empty() || cert.as_os_str().is_empty() || key.as_os_str().is_empty()
        {
            return Err("GlobalsVar 中的憑證或 URI 未正確初始化".into());
        }
        Ok((root, cert, key))
    })?;
    let root_cert = tokio::fs::read(root)
        .await
        .map_err(|_| "無法讀取 CA 根憑證")
        .inspect_err(|e| tracing::error!(?e))?;
    let client_cert = tokio::fs::read(cert)
        .await
        .map_err(|_| "無法讀取客戶端憑證")
        .inspect_err(|e| tracing::error!(?e))?;
    let client_key = tokio::fs::read(key)
        .await
        .map_err(|_| "無法讀取客戶端金鑰")
        .inspect_err(|e| tracing::error!(?e))?;

    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(root_cert))
        .identity(Identity::from_pem(client_cert, client_key));
    if cfg!(debug_assertions) {
        tls = tls.use_key_log();
    }
    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(15)),
        ..Default::default()
    };
    let opts = GrpcConnectOptions::builder()
        .connect_timeout(Duration::from_secs(5))
        .overall_timeout(Duration::from_secs(20))
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        .h2_keepalive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .http2_adaptive_window(true)
        .concurrency_limit(256)
        .initial_conn_window_size(2_097_152)
        .initial_stream_window_size(1_048_576)
        .build();
    let services: Vec<ServiceDescriptor> = GlobalConfig::with(|cfg| {
        cfg.extend
            .services_pool
            .services
            .iter()
            .flat_map(|entry| entry.value().clone().into_iter().filter(|s| s.is_server))
            .collect()
    });
    let pairs = connect_all_services(only_ca, &services, tls, backoff, &opts).await?;
    let factories = ClientFactories {
        ca:    ca::ClientCA::new,
        dns:   dns::ClientDNS::new,
        ldap:  ldap::ClientLdap::new,
        dhcp:  dhcp::ClientDhcp::new,
        agent: agent::ClientAgent::new_with_meta,
    };

    let client_map: ClientMap = build_clients_from_pairs(&pairs, &factories);
    Ok(GrpcClients::with_map(client_map))
}

pub fn build_clients_from_pairs(pairs: &PairMap, f: &ClientFactories) -> ClientMap {
    let mut out: ClientMap = HashMap::new();

    if let Some(v) = pairs.get(&ServiceKind::Mca) {
        out.insert(
            ServiceKind::Mca,
            v.iter().map(|(_, ch)| ClientHandle::Ca((f.ca)(ch.clone()))).collect(),
        );
    }
    if let Some(v) = pairs.get(&ServiceKind::Dns) {
        out.insert(
            ServiceKind::Dns,
            v.iter().map(|(_, ch)| ClientHandle::Dns((f.dns)(ch.clone()))).collect(),
        );
    }
    if let Some(v) = pairs.get(&ServiceKind::Ldap) {
        out.insert(
            ServiceKind::Ldap,
            v.iter().map(|(_, ch)| ClientHandle::Ldap((f.ldap)(ch.clone()))).collect(),
        );
    }
    if let Some(v) = pairs.get(&ServiceKind::Dhcp) {
        out.insert(
            ServiceKind::Dhcp,
            v.iter().map(|(_, ch)| ClientHandle::Dhcp((f.dhcp)(ch.clone()))).collect(),
        );
    }
    if let Some(v) = pairs.get(&ServiceKind::Agent) {
        out.insert(
            ServiceKind::Agent,
            v.iter()
                .map(|(desc, ch)| {
                    ClientHandle::Agent((f.agent)(ch.clone(), desc.uuid, desc.hostname.clone()))
                })
                .collect(),
        );
    }
    out
}
