#![allow(dead_code)]

use std::{path::PathBuf, sync::Arc};
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{sleep, Duration},
};
use tokio_util::sync::CancellationToken;

use crate::{communication::GrpcClients, server::start_grpc, ConResult, GlobalConfig};

pub struct GrpcSupervisor {
    handle:   Option<JoinHandle<ConResult<()>>>,
    cancel:   CancellationToken,
    gclients: Arc<RwLock<GrpcClients>>,
    config:   (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
}

impl GrpcSupervisor {
    pub fn new(
        gclients: Arc<RwLock<GrpcClients>>,
        config: (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
    ) -> Self {
        Self { handle: None, cancel: CancellationToken::new(), gclients, config }
    }
    async fn reload_clients(&self) {
        match GrpcClients::connect_all(false).await {
            Ok(new_gc) => {
                let mut guard = self.gclients.write().await;
                *guard = new_gc;
                tracing::info!("gRPC client 連線池已重新載入");
            }
            Err(e) => {
                tracing::error!("重建 gRPC client 連線池失敗: {e}");
            }
        }
    }

    pub async fn start(&mut self) {
        let token = self.cancel.child_token();
        self.handle =
            Some(tokio::spawn(start_grpc(token, self.gclients.clone(), self.config.clone())));
        tracing::debug!("gRPC server 已啟動");
    }

    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(h) = self.handle.take() {
            match h.await {
                Ok(Ok(())) => tracing::info!("gRPC server 已乾淨停止"),
                Ok(Err(e)) => tracing::error!("gRPC server 錯誤: {e}"),
                Err(e) => tracing::error!("gRPC server panic: {e}"),
            }
        }
        self.cancel = CancellationToken::new();
    }

    pub async fn restart(&mut self, reason: &str) {
        tracing::warn!("重啟 gRPC server，原因：{reason}");
        self.reload_clients().await;
        self.stop().await;
        self.start().await;
    }
}

pub async fn run_supervised(
    grpc_clients: Arc<RwLock<GrpcClients>>,
    config: (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>),
) -> ConResult<()> {
    let mut sup = GrpcSupervisor::new(grpc_clients, config);
    sup.start().await;
    let mut rx = GlobalConfig::subscribe_reload();
    tracing::info!("Server running… (Ctrl+C 可關閉)");
    loop {
        tokio::select! {
            res = rx.changed() => {
                if res.is_ok() {
                    sleep(Duration::from_millis(300)).await;
                    while rx.has_changed().unwrap_or(false) { let _ = rx.changed().await; }
                    sup.restart("設定重載").await;
                } else {
                    tracing::warn!("重載訂閱通道已關閉");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到 Ctrl+C，關閉…");
                sup.stop().await;
                break;
            }
        }
    }
    Ok(())
}
