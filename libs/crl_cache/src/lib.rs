use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{collections::HashSet, fmt::Debug, sync::Arc};
use thiserror::Error;
use tokio::{sync::RwLock, time::Duration};
pub mod providers;

#[derive(Debug, Error)]
pub enum CrlCacheError {
    #[error("CRL cache is empty")]
    ProviderError(String),
}

#[async_trait]
pub trait CrlProvider: Send + Sync + Debug {
    async fn fetch_crl(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<(Vec<String>, DateTime<Utc>, DateTime<Utc>), CrlCacheError>;
}

#[derive(Debug)]
pub struct CrlCache {
    entries:     RwLock<HashSet<String>>,
    last_update: RwLock<DateTime<Utc>>,
    next_update: RwLock<DateTime<Utc>>,
    provider:    Arc<dyn CrlProvider>,
}

impl CrlCache {
    /// new 时不做任何 IO，只是初始化字段
    pub fn new(
        initial_last_update: DateTime<Utc>,
        initial_next_update: DateTime<Utc>,
        provider: Arc<dyn CrlProvider + Send + Sync>,
    ) -> Self {
        Self {
            entries: RwLock::new(HashSet::new()),
            last_update: RwLock::new(initial_last_update),
            next_update: RwLock::new(initial_next_update),
            provider,
        }
    }

    pub fn with_provider(mut self, provider: Arc<dyn CrlProvider + Send + Sync>) -> Self {
        self.provider = provider;
        self
    }
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut attempt = 0;
            loop {
                match self.provider.fetch_crl(None).await {
                    Ok((full, this_u, next_u)) => {
                        {
                            let mut w = self.entries.write().await;
                            *w = full.into_iter().collect();
                        }
                        *self.last_update.write().await = this_u;
                        *self.next_update.write().await = next_u;
                        break;
                    }
                    Err(e) => {
                        attempt += 1;
                        if attempt >= 5 {
                            eprintln!("首次 CRL 拉取重試 {attempt} 次仍失敗，放棄啟動: {e}");
                            return;
                        }
                        let backoff = std::time::Duration::from_secs(2u64.pow(attempt));
                        eprintln!(
                            "首次 CRL 拉取失敗 (第 {} 次)，{} 秒後重試: {}",
                            attempt,
                            backoff.as_secs(),
                            e
                        );
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
            loop {
                let when = *self.next_update.read().await;
                let now = Utc::now();
                let dur = when.signed_duration_since(now).to_std().unwrap_or_default();
                tokio::time::sleep(dur).await;
                let since = *self.last_update.read().await;
                match self.provider.fetch_crl(Some(since)).await {
                    Ok((inc, this_u, next_u)) => {
                        let mut w = self.entries.write().await;
                        for serial in inc {
                            w.insert(serial);
                        }
                        *self.last_update.write().await = this_u;
                        *self.next_update.write().await = next_u;
                    }
                    Err(e) => {
                        eprintln!("CRL incremental refresh failed: {e}");
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                }
            }
        });
    }
    pub async fn writer(&self) -> tokio::sync::RwLockWriteGuard<'_, HashSet<String>> {
        self.entries.write().await
    }
    pub async fn reader(&self) -> tokio::sync::RwLockReadGuard<'_, HashSet<String>> {
        self.entries.read().await
    }
    pub async fn refresh(&self) -> Result<(), CrlCacheError> {
        let since = *self.last_update.read().await;
        match self.provider.fetch_crl(Some(since)).await {
            Ok((full, this_u, next_u)) => {
                let mut w = self.entries.write().await;
                *w = full.into_iter().collect();
                *self.last_update.write().await = this_u;
                *self.next_update.write().await = next_u;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    pub async fn is_revoked(&self, serial: &str) -> bool {
        self.entries.read().await.contains(serial)
    }
}
