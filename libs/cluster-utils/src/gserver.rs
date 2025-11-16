#![allow(dead_code)]
use std::time::Duration;
use sysinfo::System;
use tonic::transport::Server;

#[derive(Debug, Clone)]
pub struct GrpcTuning {
    pub concurrency_limit_per_connection: usize,
    pub max_concurrent_streams: u32,
    pub initial_stream_window_size: u32,
    pub initial_connection_window_size: u32,
    pub tcp_keepalive: Duration,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub tcp_nodelay: bool,
    pub accept_http1: bool,
}
pub fn compute_grpc_tuning() -> GrpcTuning {
    let cores = num_cpus::get().max(1);
    let mut sys = System::new();
    sys.refresh_memory();
    let mem_gib = (sys.total_memory() as f64) / (1024.0 * 1024.0);
    let concurrency = (cores * 64).clamp(64, 1024);
    let max_streams = (concurrency * 2).min(2048) as u32;
    let stream_win: u32 = if mem_gib <= 4.0 {
        256 * 1024
    } else if mem_gib <= 16.0 {
        1024 * 1024
    } else if mem_gib <= 64.0 {
        2 * 1024 * 1024
    } else {
        4 * 1024 * 1024
    };
    let factor = (concurrency / 128).clamp(2, 8) as u32;
    let mut conn_win = stream_win.saturating_mul(factor);
    let conn_cap = 16 * 1024 * 1024; // 16 MiB
    if conn_win > conn_cap {
        conn_win = conn_cap;
    }
    let low_spec = cores <= 2 || mem_gib <= 2.0;
    let http2_interval = if low_spec { Duration::from_secs(30) } else { Duration::from_secs(15) };
    let http2_timeout = if low_spec { Duration::from_secs(20) } else { Duration::from_secs(10) };
    GrpcTuning {
        concurrency_limit_per_connection: concurrency,
        max_concurrent_streams: max_streams,
        initial_stream_window_size: stream_win,
        initial_connection_window_size: conn_win,
        tcp_keepalive: Duration::from_secs(30),
        http2_keepalive_interval: http2_interval,
        http2_keepalive_timeout: http2_timeout,
        tcp_nodelay: true,
        accept_http1: false,
    }
}

pub trait GrpcTuningExt {
    fn apply_tuning(self, t: &GrpcTuning) -> Self;
}

impl GrpcTuningExt for Server {
    #[inline]
    fn apply_tuning(self, t: &GrpcTuning) -> Self {
        self.accept_http1(t.accept_http1)
            .tcp_keepalive(Some(t.tcp_keepalive))
            .tcp_nodelay(t.tcp_nodelay)
            .http2_keepalive_interval(Some(t.http2_keepalive_interval))
            .http2_keepalive_timeout(Some(t.http2_keepalive_timeout))
            .concurrency_limit_per_connection(t.concurrency_limit_per_connection)
            .max_concurrent_streams(t.max_concurrent_streams)
            .initial_connection_window_size(Some(t.initial_connection_window_size))
            .initial_stream_window_size(Some(t.initial_stream_window_size))
    }
}
pub fn grpc_with_tuning() -> Server {
    let tuning = compute_grpc_tuning();
    Server::builder().apply_tuning(&tuning)
}
