use chm_crl_cache::{CrlCache, CrlCacheError, CrlProvider};
use chm_grpc::tonic::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::sync::Arc;

use crate::cert::store::{CertificateStore, CrlEntry as StoreCrlEntry};

#[derive(Debug)]
pub struct StoreCrlProvider {
    store:         Arc<dyn CertificateStore + Send + Sync>,
    poll_interval: ChronoDuration,
}
/// 繼承 CrlProvider，從 Store 中獲取 CRL，而不從gRPC 獲取。
#[async_trait]
impl CrlProvider for StoreCrlProvider {
    async fn fetch_crl(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<(Vec<String>, DateTime<Utc>, DateTime<Utc>), CrlCacheError> {
        let entries: Vec<StoreCrlEntry> =
            self.store
                .list_crl_entries(since, usize::MAX, 0)
                .await
                .map_err(|e| CrlCacheError::ProviderError(e.to_string()))?;
        let serials: Vec<String> = entries.into_iter().filter_map(|e| e.cert_serial).collect();
        let this_u = Utc::now();
        let next_u = this_u + self.poll_interval;
        Ok((serials, this_u, next_u))
    }
}

impl StoreCrlProvider {
    pub fn new(
        store: Arc<dyn CertificateStore + Send + Sync>,
        poll_interval: ChronoDuration,
    ) -> Self {
        Self { store, poll_interval }
    }
}

/// mCA 内部 Verifier，封装 CrlCache
#[derive(Debug)]
pub struct CrlVerifier {
    cache: Arc<CrlCache>,
}

impl CrlVerifier {
    pub async fn new(
        store: Arc<dyn CertificateStore + Send + Sync>,
        poll_interval: ChronoDuration,
    ) -> Result<Self, CrlCacheError> {
        let provider = Arc::new(StoreCrlProvider::new(store.clone(), poll_interval));
        let (full, this_u, next_u) = provider.fetch_crl(None).await?;
        let cache = Arc::new(CrlCache::new(this_u, next_u, provider.clone()));
        {
            let mut w = cache.writer().await;
            *w = full.into_iter().collect();
        }
        cache.clone().start();
        Ok(CrlVerifier { cache })
    }

    pub async fn is_revoked(&self, serial: &str) -> bool {
        self.cache.is_revoked(serial).await
    }
    pub async fn reload_crl(&self) -> Result<(), CrlCacheError> {
        self.cache.refresh().await
    }
}
