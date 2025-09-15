use crate::{config::BackendConfig, globals::GlobalConfig, CaResult};
use chm_grpc::tonic::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, path::PathBuf};

pub mod sqlite;

#[derive(Debug, Clone)]
pub enum CertDer {
    Inline(Vec<u8>),
    Path(PathBuf),
}

#[derive(Debug, sqlx::Type, PartialEq)]
#[sqlx(rename_all = "lowercase")]
pub enum CertStatus {
    Valid,
    Revoked,
}

#[derive(Debug)]
pub struct Cert {
    pub serial:      Option<String>,  // PK: 憑證序號 (hex string)
    pub subject_cn:  Option<String>,  // Common Name
    pub subject_dn:  Option<String>,  // 完整 Subject DN
    pub issuer:      Option<String>,  // 完整 Issuer DN
    pub issued_date: DateTime<Utc>,   // 解析自 ISO8601
    pub expiration:  DateTime<Utc>,   // 同上
    pub thumbprint:  Option<String>,  // SHA-256 指紋 hex
    pub status:      CertStatus,      // 'valid' / 'revoked'
    pub cert_der:    Option<CertDer>, // BLOB 原始 DER bytes
}
#[derive(Debug)]
pub struct CrlEntry {
    pub cert_serial: Option<String>, // FK: 對應到 certs.serial
    pub revoked_at:  DateTime<Utc>,  // 解析自 ISO8601
    pub reason:      Option<String>, // 註銷原因
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StoreType {
    Sqlite,
    Toml,
}

#[derive(Debug)]
pub struct StoreFactory;
/// 創建憑證存儲的工廠類
impl StoreFactory {
    pub async fn create_store() -> CaResult<Box<dyn CertificateStore>> {
        let cfg = GlobalConfig::get();

        match &cfg.certificate.backend {
            BackendConfig::Sqlite { store_path, max_connections, timeout } => {
                let sqlite_cfg = BackendConfig::Sqlite {
                    store_path:      store_path.clone(),
                    max_connections: *max_connections,
                    timeout:         *timeout,
                };
                let conn = sqlite::SqlConnection::new(sqlite_cfg).await?;
                Ok(Box::new(conn))
            }
        }
    }
}

#[async_trait]
pub trait CertificateStore: Debug + Sync + Send {
    // 憑證操作相關的異步方法
    /// 列出所有憑證
    async fn list_all(&self) -> CaResult<Vec<Cert>>;
    /// 根據序列號查詢憑證
    async fn get(&self, serial: &str) -> CaResult<Option<Cert>>;
    /// 根據指紋查詢憑證
    async fn get_by_thumbprint(&self, thumbprint: &str) -> CaResult<Option<Cert>>;
    async fn get_by_common_name(&self, common_name: &str) -> CaResult<Option<Cert>>;
    /// 插入新的憑證
    async fn insert(&self, cert: openssl::x509::X509) -> CaResult<bool>;
    /// 刪除憑證
    async fn delete(&self, serial: &str) -> CaResult<bool>;
    /// 獲取憑證的狀態
    async fn query_cert_status(&self, serial: &str) -> CaResult<Option<CertStatus>>;

    // 撤銷憑證操作相關的異步方法
    /// 列出所有撤銷憑證
    async fn list_crl(&self) -> CaResult<Vec<CrlEntry>>;
    /// 分頁列出 CRL 條目，只回傳 revoked_at > `since`（若 `since` 為 None
    /// 就不加時間過濾）
    async fn list_crl_entries(
        &self,
        since: Option<DateTime<Utc>>,
        limit: usize,
        offset: usize,
    ) -> CaResult<Vec<CrlEntry>>;
    /// 將指定憑證標記為撤銷
    async fn mark_cert_revoked(&self, serial: &str, reason: Option<String>) -> CaResult<bool>;
}
