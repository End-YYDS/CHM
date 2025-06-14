use std::{str::FromStr, time::Duration};

use chrono::{DateTime, Utc};
use grpc::tonic::async_trait;
use openssl::nid::Nid;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};

use crate::{
    cert::store::{utils::hash_sha256, Cert, CertDer, CertificateStore, CrlEntry},
    CaResult,
};

pub struct SqlConnection {
    pub db_url: String, // SQLite 資料庫連線字串
    pool: SqlitePool,   // 連線池
}

impl SqlConnection {
    pub async fn new(db_url: String) -> CaResult<Self> {
        let connect_opts = SqliteConnectOptions::from_str(db_url.as_str())?
            .create_if_missing(true)
            .pragma("auto_vacuum", "FULL")
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool: SqlitePool = SqlitePoolOptions::new()
            .max_connections(5) // TODO: 從Config讀取
            .acquire_timeout(Duration::from_secs(10)) // TODO: 從Config讀取
            .connect_with(connect_opts)
            .await?;
        Ok(Self { db_url, pool })
    }
}

#[derive(Debug, sqlx::Type, PartialEq)]
#[sqlx(rename_all = "lowercase")]
pub enum CertStatus {
    Valid,
    Revoked,
}

impl std::str::FromStr for CertStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "valid" => Ok(CertStatus::Valid),
            "revoked" => Ok(CertStatus::Revoked),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}
impl std::convert::TryFrom<String> for CertStatus {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::convert::TryFrom<&str> for CertStatus {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::fmt::Display for CertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CertStatus::Valid => "valid",
            CertStatus::Revoked => "revoked",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub struct SqlCert {
    pub serial: Option<String>,     // PK: 憑證序號 (hex string)
    pub subject_cn: Option<String>, // Common Name
    pub subject_dn: Option<String>, // 完整 Subject DN
    pub issuer: Option<String>,     // 完整 Issuer DN
    pub issued_date: DateTime<Utc>, // 解析自 ISO8601
    pub expiration: DateTime<Utc>,  // 同上
    pub thumbprint: Option<String>, // SHA-256 指紋 hex
    pub status: CertStatus,         // 'valid' / 'revoked' / ...
    pub cert_der: Option<Vec<u8>>,  // BLOB 原始 DER bytes
}

impl From<SqlCert> for Cert {
    fn from(s: SqlCert) -> Self {
        Cert {
            serial: s.serial,
            subject_cn: s.subject_cn,
            subject_dn: s.subject_dn,
            issuer: s.issuer,
            issued_date: s.issued_date,
            expiration: s.expiration,
            thumbprint: s.thumbprint,
            status: s.status,
            cert_der: s.cert_der.map(CertDer::Inline),
        }
    }
}

#[derive(Debug)]
pub struct SqlCrlEntry {
    pub id: Option<i64>,             // AUTOINCREMENT 主鍵
    pub cert_serial: Option<String>, // FK: 對應到 certs.serial
    pub revoked_at: DateTime<Utc>,   // 解析自 ISO8601
    pub reason: Option<String>,      // 註銷原因
}
impl From<SqlCrlEntry> for CrlEntry {
    fn from(s: SqlCrlEntry) -> Self {
        CrlEntry {
            cert_serial: s.cert_serial,
            revoked_at: s.revoked_at,
            reason: s.reason,
        }
    }
}
#[async_trait]
#[allow(unused)]
impl CertificateStore for SqlConnection {
    // 憑證操作相關的異步方法
    /// 列出所有憑證
    async fn list_all(&self) -> CaResult<Vec<Cert>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query_as!(
            SqlCert,
            r#"
            SELECT
                serial,
                subject_cn,
                subject_dn,
                issuer,
                issued_date as "issued_date: DateTime<Utc>",
                expiration as "expiration: DateTime<Utc>",
                thumbprint,
                status as "status: CertStatus",
                cert_der
            FROM certs
            WHERE status = 'valid'
            "#
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let certs: Vec<Cert> = rows.into_iter().map(Into::into).collect();
        Ok(certs)
    }
    /// 根據序列號查詢憑證
    async fn get(&self, serial: &str) -> CaResult<Option<Cert>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as!(
            SqlCert,
            r#"
            SELECT
                serial,
                subject_cn,
                subject_dn,
                issuer,
                issued_date as "issued_date: DateTime<Utc>",
                expiration as "expiration: DateTime<Utc>",
                thumbprint,
                status as "status: CertStatus",
                cert_der
            FROM certs
            WHERE serial = ?
            "#,
            serial
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(Into::into))
    }
    /// 根據指紋查詢憑證
    async fn get_by_thumbprint(&self, thumbprint: &str) -> CaResult<Option<Cert>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as!(
            SqlCert,
            r#"
            SELECT
                serial,
                subject_cn,
                subject_dn,
                issuer,
                issued_date as "issued_date: DateTime<Utc>",
                expiration as "expiration: DateTime<Utc>",
                thumbprint,
                status as "status: CertStatus",
                cert_der
            FROM certs
            WHERE thumbprint = ?
            "#,
            thumbprint
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(Into::into))
    }
    /// 插入新的憑證
    async fn insert(&self, cert: openssl::x509::X509) -> CaResult<()> {
        let mut tx = self.pool.begin().await?;
        let serial = hash_sha256(cert.serial_number().to_bn()?.to_vec().as_slice())?;
        let subject = cert.subject_name();
        let subject_cn = subject
            .entries_by_nid(Nid::COMMONNAME)
            .filter_map(|entry| entry.data().as_utf8().ok().map(|s| s.to_string()))
            .next()
            .unwrap_or_default();
        let subject_dn: CaResult<Vec<String>> = subject
            .entries()
            .map(|entry| {
                let nid = entry.object().nid();
                let key = nid
                    .short_name()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| nid.long_name().unwrap_or("<UNKNOWN>").to_string());
                let value = entry.data().as_utf8()?.to_string();
                Ok(format!("{}={}", key, value))
            })
            .collect();
        let subject_dn = subject_dn?
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let issuer = cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .filter_map(|entry| entry.data().as_utf8().ok().map(|s| s.to_string()))
            .next()
            .unwrap_or_default();
        let issued_date = cert.not_before().to_string();
        let issued_date = issued_date.replace("GMT", "+0000");
        let issued_date = chrono::DateTime::parse_from_str(&issued_date, "%b %e %H:%M:%S %Y %z")
            .map_err(|e| format!("Failed to parse fixed-offset: {}", e))?;
        let issued_date: chrono::DateTime<chrono::Utc> = issued_date.with_timezone(&chrono::Utc);
        let expiration = cert.not_after().to_string();
        let expiration = expiration.replace("GMT", "+0000");
        let expiration = chrono::DateTime::parse_from_str(&expiration, "%b %e %H:%M:%S %Y %z")?;
        let expiration = expiration.with_timezone(&chrono::Utc);
        let cert_der = cert.to_der()?;
        let thumbprint = hash_sha256(cert_der.as_slice())?;
        let result = sqlx::query!("
        INSERT INTO certs (serial, subject_cn, subject_dn, issuer, issued_date, expiration, thumbprint,cert_der)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        serial,subject_cn,subject_dn,issuer,issued_date,expiration,thumbprint,cert_der)
        .execute(&mut *tx).await?;
        if result.rows_affected() == 0 {
            return Err("Failed to insert cert".into());
        }
        println!(
            "憑證已成功插入,序號: {}, ID: {}",
            serial,
            result.last_insert_rowid()
        );
        tx.commit().await?;
        Ok(())
    }
    /// 刪除憑證
    async fn delete(&self, serial: &str) -> CaResult<()> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query!("DELETE FROM certs WHERE serial = ?", serial)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err("No cert found with the given serial".into());
        }
        println!("憑證已成功刪除,序號: {}", serial);
        tx.commit().await?;
        Ok(())
    }

    // 撤銷憑證操作相關的異步方法
    /// 列出所有撤銷憑證
    async fn list_crl(&self) -> CaResult<Vec<CrlEntry>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query_as!(
            SqlCrlEntry,
            r#"
            SELECT
                id,
                cert_serial,
                revoked_at as "revoked_at: DateTime<Utc>",
                reason
            FROM crl_entries
            "#
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    /// 將指定憑證標記為撤銷
    async fn mark_cert_revoked(&self, serial: &str, reason: Option<String>) -> CaResult<()> {
        let mut tx = self.pool.begin().await?;
        let is_revoked = self.query_cert_status(serial).await?;
        if is_revoked.is_some() && is_revoked.unwrap() == CertStatus::Revoked {
            return Err("憑證已經被標記為註銷".into());
        }
        let now = chrono::Utc::now();
        let result = sqlx::query!(
            "INSERT INTO crl_entries (cert_serial, revoked_at, reason) VALUES (?, ?, ?)",
            serial,
            now,
            reason
        )
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err("Failed to insert CRL entry".into());
        }

        let update_result = sqlx::query!(
            "UPDATE certs SET status = 'revoked' WHERE serial = ?",
            serial
        )
        .execute(&mut *tx)
        .await?;

        if update_result.rows_affected() == 0 {
            return Err("No cert found with the given serial to update".into());
        }
        tx.commit().await?;

        println!("憑證已成功標記為註銷,序號: {}", serial);
        Ok(())
    }
    async fn query_cert_status(&self, serial: &str) -> CaResult<Option<CertStatus>> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query!("SELECT status FROM certs WHERE serial = ?", serial)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;

        match result {
            Some(row) => Ok(Some(row.status.try_into()?)),
            None => Ok(None),
        }
    }
}
