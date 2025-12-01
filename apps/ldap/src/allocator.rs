use crate::error::SrvResult;
use ldap3::{Ldap, Scope, SearchEntry};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};
use std::time::Duration;
use tokio::sync::OnceCell;

pub static GLOBAL_ALLOCATOR: OnceCell<Allocator> = OnceCell::const_new();

pub struct Allocator {
    db_path:         String,
    max_connections: u32,
    timeout:         u64,
    uid_start:       i64,
    gid_start:       i64,
    pool:            OnceCell<SqlitePool>,
}

impl Allocator {
    pub const fn new(
        db_path: String,
        max_connections: u32,
        timeout: u64,
        uid_start: i64,
        gid_start: i64,
    ) -> Self {
        Self {
            db_path,
            max_connections,
            timeout,
            uid_start,
            gid_start,
            pool: OnceCell::const_new(),
        }
    }
    async fn init_pool(&self) -> SrvResult<SqlitePool> {
        let timeout_string = self.timeout.to_string();
        let connect_opts = SqliteConnectOptions::new()
            .filename(&self.db_path)
            .create_if_missing(true)
            .pragma("auto_vacuum", "FULL")
            .pragma("synchronous", "NORMAL")
            .pragma("busy_timeout", timeout_string)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool: SqlitePool = SqlitePoolOptions::new()
            .max_connections(self.max_connections)
            .acquire_timeout(Duration::from_secs(self.timeout))
            .connect_with(connect_opts)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        sqlx::query("INSERT OR IGNORE INTO id_alloc(kind,next) VALUES('uid', ?)")
            .bind(self.uid_start)
            .execute(&pool)
            .await?;

        sqlx::query("INSERT OR IGNORE INTO id_alloc(kind,next) VALUES('gid', ?)")
            .bind(self.gid_start)
            .execute(&pool)
            .await?;
        Ok(pool)
    }
    pub async fn pool(&self) -> SrvResult<&SqlitePool> {
        self.pool.get_or_try_init(|| async { self.init_pool().await }).await
    }
    pub async fn alloc_next(&self, kind: &str) -> SrvResult<i64> {
        let pool = self.pool().await?;
        let row = sqlx::query!(
            r#"
        UPDATE id_alloc
        SET next = next + 1
        WHERE kind = ?1
        RETURNING next - 1 as "allocated!: i64"
        "#,
            kind
        )
        .fetch_one(pool)
        .await?;

        Ok(row.allocated)
    }

    pub async fn alloc_uid(&self) -> SrvResult<i64> {
        self.alloc_next("uid").await
    }

    pub async fn alloc_gid(&self) -> SrvResult<i64> {
        self.alloc_next("gid").await
    }
    pub async fn reseed_from_ldap(&self, ldap: &Ldap, base_dn: &str) -> SrvResult<()> {
        let pool = self.pool().await?;

        let (max_uid, max_gid) = max_uid_gid(ldap, base_dn).await?;
        let target_uid_next = (max_uid + 1).max(self.uid_start);
        let target_gid_next = (max_gid + 1).max(self.gid_start);
        sqlx::query!(
            r#"
            UPDATE id_alloc
               SET next = ?1
             WHERE kind = 'uid'
               AND next < ?1
            "#,
            target_uid_next
        )
        .execute(pool)
        .await?;
        sqlx::query!(
            r#"
            UPDATE id_alloc
               SET next = ?1
             WHERE kind = 'gid'
               AND next < ?1
            "#,
            target_gid_next
        )
        .execute(pool)
        .await?;

        Ok(())
    }
    pub async fn bump_gid_next_to(&self, min_next: i64) -> SrvResult<()> {
        let pool = self.pool().await?;
        sqlx::query!(
            r#"
            UPDATE id_alloc
               SET next = ?1
             WHERE kind = 'gid'
               AND next < ?1
            "#,
            min_next
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}

async fn max_uid_gid(ldap: &Ldap, base_dn: &str) -> SrvResult<(i64, i64)> {
    let mut ldap = ldap.clone();
    let (rs, _res) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(|(objectClass=posixAccount)(objectClass=posixGroup))",
            vec!["uidNumber", "gidNumber"],
        )
        .await?
        .success()?;

    let mut max_uid: i64 = 0;
    let mut max_gid: i64 = 0;

    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(vals) = se.attrs.get("uidNumber") {
            for v in vals {
                if let Ok(n) = v.parse::<i64>() {
                    if n > max_uid {
                        max_uid = n;
                    }
                }
            }
        }
        if let Some(vals) = se.attrs.get("gidNumber") {
            for v in vals {
                if let Ok(n) = v.parse::<i64>() {
                    if n > max_gid {
                        max_gid = n;
                    }
                }
            }
        }
    }
    Ok((max_uid, max_gid))
}
pub async fn get_allocator() -> &'static Allocator {
    let (db_path, max_connections, timeout, uid_start, gid_start) =
        crate::globals::GlobalConfig::with(|cfg| {
            let db_path = cfg.extend.ids.store_path.clone().display().to_string();
            let max_connections = cfg.extend.ids.max_connections;
            let timeout = cfg.extend.ids.timeout;
            let uid_start = cfg.extend.allocator.uid_start;
            let gid_start = cfg.extend.allocator.gid_start;
            (db_path, max_connections, timeout, uid_start, gid_start)
        });
    GLOBAL_ALLOCATOR
        .get_or_init(|| async {
            Allocator::new(db_path, max_connections, timeout, uid_start, gid_start)
        })
        .await
}
