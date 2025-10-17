use chm_grpc::tonic::async_trait;
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
        limit: usize,
        offset: usize,
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
            let page_size: usize = 500;
            let initial_max_retries = 5;
            let incremental_max_retries = 5;
            let mut initial_attempt = 0;
            let (mut this_update, mut next_update) =
                (Utc::now(), Utc::now() + Duration::from_secs(3600));

            'initial: loop {
                let mut all_serials = Vec::new();
                let mut offset = 0;
                let mut page_error = None;
                while page_error.is_none() {
                    match self.provider.fetch_crl(None, page_size, offset).await {
                        Ok((page, tu, nu)) => {
                            if offset == 0 {
                                this_update = tu;
                                next_update = nu;
                            }
                            if page.is_empty() {
                                break;
                            }
                            all_serials.extend(page);
                            offset += page_size;
                        }
                        Err(e) => {
                            page_error = Some(e);
                        }
                    }
                }
                if page_error.is_none() {
                    {
                        let mut w = self.entries.write().await;
                        *w = all_serials.into_iter().collect();
                    }
                    *self.last_update.write().await = this_update;
                    *self.next_update.write().await = next_update;
                    break 'initial;
                }
                initial_attempt += 1;
                if initial_attempt >= initial_max_retries {
                    eprintln!(
                        "首次 CRL 全量載入重試 {} 次後仍失敗，放棄啟動: {:?}",
                        initial_max_retries,
                        page_error.unwrap()
                    );
                    return;
                }
                let backoff = std::time::Duration::from_secs(2u64.pow(initial_attempt));
                eprintln!(
                    "首次 CRL 全量載入失敗 (第 {} 次)，{} 秒後重試: {:?}",
                    initial_attempt,
                    backoff.as_secs(),
                    page_error.unwrap()
                );
                tokio::time::sleep(backoff).await;
            }
            loop {
                let when = *self.next_update.read().await;
                let now = Utc::now();
                let dur = when.signed_duration_since(now).to_std().unwrap_or_default();
                tokio::time::sleep(dur).await;

                let since = *self.last_update.read().await;
                let mut retry = 0;

                'incremental: loop {
                    let mut inc_serials = Vec::new();
                    let mut offset = 0;
                    let mut page_error = None;
                    let mut tu_opt = None;
                    let mut nu_opt = None;

                    while page_error.is_none() {
                        match self.provider.fetch_crl(Some(since), page_size, offset).await {
                            Ok((page, tu, nu)) => {
                                if offset == 0 {
                                    tu_opt = Some(tu);
                                    nu_opt = Some(nu);
                                }
                                inc_serials.extend(page.clone());
                                offset += page_size;
                                if page.len() < page_size {
                                    break;
                                }
                            }
                            Err(e) => {
                                page_error = Some(e);
                            }
                        }
                    }
                    if page_error.is_none() {
                        let mut w = self.entries.write().await;
                        for s in inc_serials {
                            w.insert(s);
                        }
                        *self.last_update.write().await = tu_opt.unwrap();
                        *self.next_update.write().await = nu_opt.unwrap();
                        break 'incremental;
                    }
                    retry += 1;
                    if retry >= incremental_max_retries {
                        eprintln!(
                            "CRL 增量更新已重試 {} 次仍失敗，放棄本次更新: {:?}",
                            incremental_max_retries,
                            page_error.unwrap()
                        );
                        break 'incremental;
                    }
                    let backoff = std::time::Duration::from_secs(2u64.pow(retry));
                    eprintln!(
                        "CRL 增量更新失敗 (第 {} 次)，{} 秒後重試: {:?}",
                        retry,
                        backoff.as_secs(),
                        page_error.unwrap()
                    );
                    tokio::time::sleep(backoff).await;
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
    /// 手動觸發一次「全量」CRL 載入，並支援分頁 & 重試
    pub async fn refresh(&self) -> Result<(), CrlCacheError> {
        let page_size: usize = 500;
        let max_retries = 5;
        let mut attempt = 0;
        loop {
            let mut all_serials = Vec::new();
            let mut offset = 0;
            let mut page_error: Option<CrlCacheError> = None;
            let mut this_u: Option<DateTime<Utc>> = None;
            let mut next_u: Option<DateTime<Utc>> = None;

            while page_error.is_none() {
                match self.provider.fetch_crl(None, page_size, offset).await {
                    Ok((page, tu, nu)) => {
                        if offset == 0 {
                            this_u = Some(tu);
                            next_u = Some(nu);
                        }
                        if page.is_empty() {
                            break;
                        }
                        all_serials.extend(page);
                        offset += page_size;
                    }
                    Err(e) => {
                        page_error = Some(e);
                    }
                }
            }

            if page_error.is_none() {
                {
                    let mut w = self.entries.write().await;
                    *w = all_serials.into_iter().collect();
                }
                *self.last_update.write().await = this_u.unwrap();
                *self.next_update.write().await = next_u.unwrap();
                return Ok(());
            }
            attempt += 1;
            let err = page_error.unwrap();
            if attempt >= max_retries {
                eprintln!("手動 refresh 全量載入重試 {max_retries} 次後仍失敗: {err:?}");
                return Err(err);
            }
            let backoff = Duration::from_secs(2u64.pow(attempt));
            eprintln!(
                "手動 refresh 全量載入失敗 (第 {attempt} 次)，{} 秒後重試: {err:?}",
                backoff.as_secs(),
            );
            tokio::time::sleep(backoff).await;
        }
    }
    pub async fn is_revoked(&self, serial: &str) -> bool {
        self.entries.read().await.contains(serial)
    }
}
