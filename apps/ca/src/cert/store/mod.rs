use std::path::PathBuf;

use crate::{cert::store::sqlite::CertStatus, CaResult};
use chrono::{DateTime, Utc};
use grpc::tonic::async_trait;

pub mod sqlite;
pub mod toml;
pub mod utils;

#[derive(Debug, Clone)]
pub enum CertDer {
    Inline(Vec<u8>),
    Path(PathBuf),
}
// /// Implementing the `sqlx::Type` trait for `CertDer` to handle database storage
// impl sqlx::Type<sqlx::Sqlite> for CertDer {
//     fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
//         <Vec<u8> as sqlx::Type<Sqlite>>::type_info()
//     }
// }
// /// Implementing the `sqlx::Decode` trait for `CertDer` to handle decoding
// impl<'r> Decode<'r, Sqlite> for CertDer {
//     fn decode(
//         value: <Sqlite as sqlx::Database>::ValueRef<'r>,
//     ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
//         let bytes = <Vec<u8> as Decode<Sqlite>>::decode(value)?;
//         Ok(CertDer::Inline(bytes))
//     }
// }

#[derive(Debug)]
pub struct Cert {
    pub serial: Option<String>,     // PK: 憑證序號 (hex string)
    pub subject_cn: Option<String>, // Common Name
    pub subject_dn: Option<String>, // 完整 Subject DN
    pub issuer: Option<String>,     // 完整 Issuer DN
    pub issued_date: DateTime<Utc>, // 解析自 ISO8601
    pub expiration: DateTime<Utc>,  // 同上
    pub thumbprint: Option<String>, // SHA-256 指紋 hex
    pub status: CertStatus,         // 'valid' / 'revoked' / ...
    pub cert_der: Option<CertDer>,  // BLOB 原始 DER bytes
}
#[derive(Debug)]
pub struct CrlEntry {
    pub cert_serial: Option<String>, // FK: 對應到 certs.serial
    pub revoked_at: DateTime<Utc>,   // 解析自 ISO8601
    pub reason: Option<String>,      // 註銷原因
}

#[async_trait]
pub trait CertificateStore {
    // 憑證操作相關的異步方法
    /// 列出所有憑證
    async fn list_all(&self) -> CaResult<Vec<Cert>>;
    /// 根據序列號查詢憑證
    async fn get(&self, serial: &str) -> CaResult<Option<Cert>>;
    /// 根據指紋查詢憑證
    async fn get_by_thumbprint(&self, thumbprint: &str) -> CaResult<Option<Cert>>;
    /// 插入新的憑證
    async fn insert(&self, cert: openssl::x509::X509) -> CaResult<()>;
    /// 刪除憑證
    async fn delete(&self, serial: &str) -> CaResult<()>;
    /// 獲取憑證的狀態
    async fn query_cert_status(&self, serial: &str) -> CaResult<Option<CertStatus>>;

    // 撤銷憑證操作相關的異步方法
    /// 列出所有撤銷憑證
    async fn list_crl(&self) -> CaResult<Vec<CrlEntry>>;
    /// 將指定憑證標記為撤銷
    async fn mark_cert_revoked(&self, serial: &str, reason: Option<String>) -> CaResult<()>;

}
